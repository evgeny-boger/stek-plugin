"""Interfaces shared by real and test-only backends."""
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

_HEX = re.compile(r"^[0-9a-f]+$")


@dataclass
class Certificate:
    serial_hex: str                 # lowercase hex, no 0x, no separators
    thumbprint: str                 # lowercase SHA-1 hex
    subject_full: str = ""
    subject_name: str = ""
    issuer_full: str = ""
    issuer_name: str = ""
    subject_fio: str = ""
    valid_from: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    valid_to: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    der: bytes = b""
    has_private_key: bool = True
    inn: str = ""                   # INN or INNLE of the subject
    qualified: bool = True          # subject carries a Russian ID OID (ENUMCERTS filter)


def normalize_serial(value: str) -> str:
    """CertSN normalization recovered from 0x46c170: drop ':' and ' ',
    lowercase; additionally tolerate a '0x' prefix and leading zeros when
    comparing."""
    value = value.replace(":", "").replace(" ", "").strip().lower()
    if value.startswith("0x"):
        value = value[2:]
    return value


def serials_equal(a: str, b: str) -> bool:
    return normalize_serial(a).lstrip("0") == normalize_serial(b).lstrip("0")


def is_thumbprint(value: str) -> bool:
    value = normalize_serial(value)
    return len(value) == 40 and bool(_HEX.match(value))


def is_serial(value: str) -> bool:
    value = normalize_serial(value)
    return bool(value) and bool(_HEX.match(value))


class CryptoBackend:
    def execute_task(self, task):
        raise NotImplementedError

    def certificates(self, only_private=True, inn="", only_valid=False,
                     qualified_only=True):
        raise NotImplementedError

    @staticmethod
    def validate_selector(serial="", thumbprint=""):
        """Reject values that are not hex before they reach the CSP (argv)."""
        if thumbprint:
            return is_thumbprint(thumbprint)
        if serial:
            return is_serial(serial)
        return True

    def certificate(self, serial="", thumbprint=""):
        # Direct lookup ignores the ENUMCERTS "qualified" filter (the original
        # returns non-qualified certs like CN=mykey via GETCERTBODY).
        thumbprint = normalize_serial(thumbprint)
        certs = sorted(self.certificates(False, qualified_only=False),
                       key=lambda c: not c.has_private_key)
        for cert in certs:
            if thumbprint and cert.thumbprint.lower() == thumbprint:
                return cert
            if serial and serials_equal(cert.serial_hex, serial):
                return cert
        return None
