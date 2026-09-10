"""Parameter parsing identical to the original plugin.

The original splits `UnparsedParams` on '&' and decodes each value with
TIdURI.URLDecode (so '+' becomes a space, exactly like `parse_qsl`).  Keys
are compared case-sensitively (CertSN, CertThumb, TaskId, Id, taskId, inn,
onlyValid, fss_nom).
"""
from urllib.parse import parse_qsl

KNOWN_PARAMS = frozenset({"CertSN", "CertThumb", "TaskId", "Id", "taskId", "inn",
                          "onlyValid", "fss_nom"})


def parse_params(raw: str) -> "list[tuple[str, str]]":
    return parse_qsl(raw, keep_blank_values=True, strict_parsing=False,
                     encoding="utf-8", errors="replace")


class Params:
    """FPC TStringList-like parameter access."""

    def __init__(self, raw: str):
        self.pairs = parse_params(raw)

    def index_of(self, name: str) -> int:
        for i, (k, _) in enumerate(self.pairs):
            if k == name:
                return i
        return -1

    def has(self, *names) -> bool:
        return any(self.index_of(n) >= 0 for n in names)

    def value(self, name: str, default: str = "") -> str:
        i = self.index_of(name)
        return self.pairs[i][1] if i >= 0 else default

    def has_known(self) -> bool:
        return any(k in KNOWN_PARAMS for k, _ in self.pairs)

    def document(self) -> bytes:
        """Form-encoded POST: the document is the (last) value whose key is
        not a protocol parameter, e.g. `Data=<base64>`.  Never a known key."""
        for k, v in reversed(self.pairs):
            if k not in KNOWN_PARAMS and v:
                return v.encode("utf-8", "surrogateescape")
        return b""
