from .base import Certificate, CryptoBackend
from .csp import CSPError, CryptoProBackend
from .pycades_backend import PycadesBackend, is_available as pycades_available


def default_backend(pin=None, store=None):
    """pycades (official CryptoPro Python binding) when importable, else the
    cryptcp/certmgr command-line adapter.

    pycades calls run in-process and cannot be timed out, so an unanswered
    PIN dialog blocks the plugin; without a configured PIN and without a
    display for the CSP dialog, the subprocess adapter (600 s timeout) is the
    safer default.
    """
    import os
    headless = not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    pin = pin if pin is not None else os.environ.get("STEK_CSP_PIN")
    if pycades_available() and (pin or not headless):
        return PycadesBackend(store_name=store, pin=pin)
    return CryptoProBackend(store=store or "uMy", pin=pin)


__all__ = ["Certificate", "CryptoBackend", "CSPError", "CryptoProBackend",
           "PycadesBackend", "pycades_available", "default_backend"]
