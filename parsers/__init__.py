# parsers/__init__.py
# SOC L1 Log Analysis — Parsers Module

from .parse_auth    import parse_auth_log
from .parse_evtx    import parse_windows_events
from .parse_web     import parse_web_log
from .parse_dns     import parse_dns_log
from .parse_syslog  import parse_syslog

__all__ = [
    "parse_auth_log",
    "parse_windows_events",
    "parse_web_log",
    "parse_dns_log",
    "parse_syslog",
]
