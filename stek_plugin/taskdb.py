"""CRYPTO_TASKS queue: a small SQLite-backed task table plus a worker thread.

Column names follow the original plugin's table, but nothing depends on its
file format: timestamps are ISO-8601 text, and `--db :memory:` gives a pure
in-memory queue.  The table exists so that async tasks survive a restart
while a client is still polling GETRESULT, and to serve GETLOGINFO history
(rows are purged after TASK_TTL_DAYS, blobs after TASK_BLOB_TTL_DAYS).
"""
import logging
import sqlite3
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from . import (STATUS_ERROR, STATUS_NEW, STATUS_SUCCESS, STATUS_WAIT,
               TASK_BLOB_TTL_DAYS, TASK_POLL_INTERVAL, TASK_TTL_DAYS)

log = logging.getLogger("stek_plugin")
CLEANUP_INTERVAL = 3600.0

SCHEMA = """CREATE TABLE IF NOT EXISTS CRYPTO_TASKS (
 ID TEXT PRIMARY KEY, TTYPE INTEGER NOT NULL, START_TIME TEXT NOT NULL,
 STATUS INTEGER NOT NULL, CERT_SN TEXT, CERT_THUMB TEXT, STR_PARAM TEXT,
 IN_DATA BLOB, OUT_DATA BLOB, MODIFY_TIME TEXT)"""
COLUMNS = ("ID,TTYPE,START_TIME,STATUS,CERT_SN,CERT_THUMB,STR_PARAM,"
           "IN_DATA,OUT_DATA,MODIFY_TIME")
SELECT = f"SELECT {COLUMNS} FROM CRYPTO_TASKS"
TIME_FMT = "%Y-%m-%d %H:%M:%S"


def new_task_id() -> str:
    """Task id format of the original (0xa99d40 + LowerCase): a GUID with
    its groups reordered and the last group cut to 11 hex digits, 31
    lowercase hex characters in total."""
    h = uuid.uuid4().hex
    return h[20:31] + h[16:20] + h[12:16] + h[8:12] + h[:8]


def normalize_task_id(value: str) -> str:
    """Client-supplied TaskId: braces/dashes stripped, lowercased, bounded."""
    return "".join(ch for ch in value if ch not in "{}-").strip().lower()[:40]


def _now() -> str:
    return datetime.now().strftime(TIME_FMT)


def _parse(text) -> Optional[datetime]:
    try:
        return datetime.strptime(text, TIME_FMT) if text else None
    except ValueError:
        return None


@dataclass
class Task:
    id: str
    ttype: int
    cert_sn: str = ""
    cert_thumb: str = ""
    str_param: str = ""
    in_data: bytes = b""
    out_data: bytes = b""       # result, or the error text for STATUS_ERROR
    status: int = STATUS_NEW
    start_time: datetime = field(default_factory=datetime.now)
    modify_time: Optional[datetime] = None

    @property
    def error(self) -> str:
        return self.out_data.decode("utf-8", "replace") if self.status == STATUS_ERROR else ""


class TaskDB:
    """All access is serialized with one lock; the connection is shared by
    the HTTP threads and the worker."""

    def __init__(self, path: str):
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.execute(SCHEMA)
        self._conn.commit()

    def insert(self, task: Task, queued: bool = True) -> None:
        task.status = STATUS_WAIT if queued else STATUS_NEW
        task.start_time = task.modify_time = datetime.now()
        with self._lock:
            self._conn.execute(
                f"INSERT OR REPLACE INTO CRYPTO_TASKS ({COLUMNS}) VALUES (?,?,?,?,?,?,?,?,?,?)",
                (task.id, task.ttype, _now(), task.status, task.cert_sn, task.cert_thumb,
                 task.str_param, task.in_data, None, _now()))
            self._conn.commit()

    @staticmethod
    def _row_to_task(row) -> Task:
        rid, ttype, start, status, sn, thumb, param, in_data, out_data, modify = row
        return Task(id=rid, ttype=ttype, status=status, cert_sn=sn or "",
                    cert_thumb=thumb or "", str_param=param or "",
                    in_data=bytes(in_data or b""), out_data=bytes(out_data or b""),
                    start_time=_parse(start) or datetime.now(), modify_time=_parse(modify))

    def _select(self, where: str = "", params=()):
        with self._lock:
            rows = self._conn.execute(f"{SELECT} {where}", params).fetchall()
        return [self._row_to_task(r) for r in rows]

    def get(self, task_id: str) -> Optional[Task]:
        rows = self._select("WHERE ID=?", (task_id,))
        return rows[0] if rows else None

    def list_all(self):
        return self._select("ORDER BY START_TIME DESC")

    def next_queued(self) -> Optional[Task]:
        rows = self._select("WHERE STATUS=? ORDER BY START_TIME LIMIT 1", (STATUS_WAIT,))
        return rows[0] if rows else None

    def set_result(self, task_id: str, status: int, out_data: bytes) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE CRYPTO_TASKS SET STATUS=?, OUT_DATA=?, MODIFY_TIME=? WHERE ID=?",
                (status, out_data, _now(), task_id))
            self._conn.commit()

    def wait_status(self, task_id: str, timeout: float) -> Optional[Task]:
        deadline = time.monotonic() + timeout
        while True:
            task = self.get(task_id)
            if task is None or task.status in (STATUS_SUCCESS, STATUS_ERROR) \
                    or time.monotonic() >= deadline:
                return task
            time.sleep(TASK_POLL_INTERVAL)

    def fail_stale(self) -> None:
        """Задачи, оставшиеся New/Wait после перезапуска, помечаем ошибкой,
        чтобы фоновой воркер не переподписал/перерасшифровал их без клиента."""
        with self._lock:
            self._conn.execute(
                "UPDATE CRYPTO_TASKS SET STATUS=?, OUT_DATA=?, MODIFY_TIME=? "
                "WHERE STATUS IN (?, ?)",
                (STATUS_ERROR, "прервано при перезапуске службы".encode(),
                 _now(), STATUS_NEW, STATUS_WAIT))
            self._conn.commit()

    def cleanup(self) -> None:
        now = datetime.now()
        with self._lock:
            self._conn.execute(
                "UPDATE CRYPTO_TASKS SET IN_DATA=NULL, OUT_DATA=NULL WHERE START_TIME < ?",
                ((now - timedelta(days=TASK_BLOB_TTL_DAYS)).strftime(TIME_FMT),))
            self._conn.execute(
                "DELETE FROM CRYPTO_TASKS WHERE START_TIME < ?",
                ((now - timedelta(days=TASK_TTL_DAYS)).strftime(TIME_FMT),))
            self._conn.commit()

    def close(self):
        with self._lock:
            self._conn.close()


class TaskWorker:
    """Runs queued tasks through the crypto backend in a background thread."""

    def __init__(self, db: TaskDB, backend):
        self.db = db
        self.backend = backend
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True, name="StekTaskWorker")

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread.is_alive() and threading.current_thread() is not self._thread:
            self._thread.join(timeout=2)

    def _run(self):
        next_cleanup = time.monotonic() + CLEANUP_INTERVAL
        while not self._stop.is_set():
            try:
                if time.monotonic() >= next_cleanup:
                    self.db.cleanup()
                    next_cleanup = time.monotonic() + CLEANUP_INTERVAL
                task = self.db.next_queued()
            except sqlite3.Error as exc:
                log.error("task queue unavailable: %s", exc)
                task = None
            if task is None:
                time.sleep(TASK_POLL_INTERVAL)
                continue
            self.execute(task)

    def execute(self, task: Task) -> Task:
        try:
            task.out_data = self.backend.execute_task(task)
            task.status = STATUS_SUCCESS
        except Exception as exc:  # noqa: BLE001 - every failure becomes the task error
            task.out_data = (str(exc) or exc.__class__.__name__).encode("utf-8", "replace")
            task.status = STATUS_ERROR
            log.info("task %s failed: %s", task.id, task.error)
        try:
            self.db.set_result(task.id, task.status, task.out_data)
        except sqlite3.Error as exc:   # DB closed during shutdown
            log.error("cannot store result of task %s: %s", task.id, exc)
        return task

    def execute_sync(self, task: Task) -> Task:
        """_SYNC flow: insert, run inline in the HTTP thread, store the result."""
        self.db.insert(task, queued=False)
        return self.execute(task)
