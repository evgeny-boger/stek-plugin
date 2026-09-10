import argparse
import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from . import BIND_HOST, BIND_PORT, DB_NAME, LOG_NAME
from .backends import CryptoProBackend, PycadesBackend, default_backend
from .server import Plugin, serve


def main():
    parser = argparse.ArgumentParser(description="Python reproduction of Стэк.Плагин")
    parser.add_argument("--host", default=BIND_HOST)
    parser.add_argument("--port", type=int, default=BIND_PORT)
    parser.add_argument("--db", default=DB_NAME, help="SQLite task queue (':memory:' for none)")
    parser.add_argument("--log", default=LOG_NAME,
                        help="log file, or '-' for stderr (systemd/journald)")
    parser.add_argument("--backend", choices=("auto", "pycades", "cryptcp"), default="auto")
    parser.add_argument("--store", default=None,
                        help="certificate store: 'My' (pycades) / 'uMy' (cryptcp)")
    parser.add_argument("--pin", default=None,
                        help="key container PIN (default: env STEK_CSP_PIN, otherwise the "
                             "CSP asks interactively). WARNING: with a stored PIN any web "
                             "page can sign/decrypt with your key without confirmation; "
                             "the CSP dialog is the only per-operation consent")
    args = parser.parse_args()
    if args.log == "-":
        # journald adds its own timestamp; keep the line lean.
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        logging.basicConfig(level=logging.INFO, handlers=[handler])
    else:
        fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
        file_handler = RotatingFileHandler(args.log, maxBytes=5 * 1024 * 1024, backupCount=2)
        file_handler.setFormatter(fmt)
        console = logging.StreamHandler()
        console.setLevel(logging.WARNING)  # warnings/errors are visible in the terminal
        console.setFormatter(fmt)
        logging.basicConfig(level=logging.INFO, handlers=[file_handler, console])
    if args.pin or os.environ.get("STEK_CSP_PIN"):
        logging.getLogger("stek_plugin").warning(
            "PIN supplied: signing/decryption will not ask for confirmation")
    if args.backend == "pycades":
        backend = PycadesBackend(store_name=args.store, pin=args.pin)
    elif args.backend == "cryptcp":
        backend = CryptoProBackend(store=args.store or "uMy", pin=args.pin)
    else:
        backend = default_backend(pin=args.pin, store=args.store)
    logging.getLogger("stek_plugin").info("backend: %s", backend.__class__.__name__)
    plugin = Plugin(backend, args.db, args.log)
    serve(plugin, args.host, args.port)


if __name__ == "__main__":
    main()
