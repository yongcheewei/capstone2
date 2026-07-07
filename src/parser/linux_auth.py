from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Iterable, Iterator, List, Optional


SYSLOG_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<service>[^\[\s]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.*)$"
)

FAILED_PASSWORD_RE = re.compile(
    r"Failed password for (?P<user_status>invalid user )?(?P<user>\S+) from "
    r"(?P<ip>\S+) port (?P<port>\d+) ssh2"
)

ACCEPTED_PASSWORD_RE = re.compile(
    r"Accepted password for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+) ssh2"
)

INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)

CONNECTION_CLOSED_RE = re.compile(
    r"Connection closed by authenticating user (?P<user>\S+) (?P<ip>\S+) port "
    r"(?P<port>\d+) \[preauth\]"
)

AUTH_FAILURE_PAM_RE = re.compile(
    r"pam_unix\(sshd:auth\):\s+authentication failure.*?(?:user=(?P<user>\S+))?.*?"
    r"(?:rhost=(?P<rhost>\S+))?"
)


@dataclass
class AuthEvent:
    """Structured representation of one parsed syslog sshd event."""

    timestamp: Optional[str]
    year: int
    host: str
    service: str
    pid: Optional[int]
    raw: str
    event_type: str
    user: Optional[str] = None
    ip: Optional[str] = None
    port: Optional[int] = None
    invalid_user: bool = False

    def as_dict(self) -> dict:
        return asdict(self)


_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


def _guess_year(month: str, reference: Optional[datetime] = None) -> int:
    """Linux auth.log has no year. Use the current year unless the
    reference month is in the future, in which case assume previous year.
    """
    ref = reference or datetime.now()
    if month not in _MONTHS:
        return ref.year
    if _MONTHS[month] > ref.month and ref.month == 1 and month == "Dec":
        return ref.year - 1
    if _MONTHS[month] > ref.month:
        return ref.year - 1
    return ref.year


def _to_ts(year: int, month: str, day: str, time_str: str) -> Optional[str]:
    try:
        dt = datetime(year, _MONTHS[month], int(day),
                      *map(int, time_str.split(":")))
        return dt.isoformat()
    except (ValueError, KeyError):
        return None


def _classify(message: str) -> Optional[dict]:
    """Return subtype dict, or None if line is not auth-relevant."""
    m = FAILED_PASSWORD_RE.search(message)
    if m:
        d = m.groupdict()
        return {
            "event_type": "failed_password",
            "user": d["user"],
            "ip": d["ip"],
            "port": int(d["port"]),
            "invalid_user": bool(d.get("user_status")),
        }
    m = ACCEPTED_PASSWORD_RE.search(message)
    if m:
        d = m.groupdict()
        return {
            "event_type": "accepted_password",
            "user": d["user"],
            "ip": d["ip"],
            "port": int(d["port"]),
            "invalid_user": False,
        }
    m = INVALID_USER_RE.search(message)
    if m:
        d = m.groupdict()
        return {
            "event_type": "invalid_user",
            "user": d["user"],
            "ip": d["ip"],
            "port": int(d["port"]),
            "invalid_user": True,
        }
    m = CONNECTION_CLOSED_RE.search(message)
    if m:
        d = m.groupdict()
        return {
            "event_type": "connection_closed_preauth",
            "user": d["user"],
            "ip": d["ip"],
            "port": int(d["port"]),
            "invalid_user": False,
        }
    m = AUTH_FAILURE_PAM_RE.search(message)
    if m:
        d = m.groupdict()
        return {
            "event_type": "pam_auth_failure",
            "user": d.get("user"),
            "ip": d.get("rhost"),
            "port": None,
            "invalid_user": False,
        }
    return None


def parse_line(line: str, reference: Optional[datetime] = None) -> Optional[AuthEvent]:
    """Parse one syslog line. Return AuthEvent if sshd/auth-relevant, else None."""
    line = line.rstrip("\n")
    head = SYSLOG_RE.match(line)
    if not head:
        return None
    h = head.groupdict()
    service = h["service"]
    if service not in {"sshd", "sudo", "cron"} and not service.startswith("sshd"):
        return None
    message = h["message"]
    sub = _classify(message)
    if sub is None:
        return None

    year = _guess_year(h["month"], reference)
    ts = _to_ts(year, h["month"], h["day"], h["time"])
    try:
        pid = int(h["pid"]) if h["pid"] else None
    except (TypeError, ValueError):
        pid = None

    return AuthEvent(
        timestamp=ts,
        year=year,
        host=h["host"],
        service=service,
        pid=pid,
        raw=line,
        **sub,
    )


def parse_file(path: str | Path | Iterable[str],
               reference: Optional[datetime] = None) -> List[AuthEvent]:
    """Parse a syslog file or stream of lines, returning all auth events."""
    if isinstance(path, (str, Path)):
        p = Path(path)
        with p.open("r", encoding="utf-8", errors="replace") as fh:
            return list(parse_iter(fh, reference))
    return list(parse_iter(path, reference))


def parse_iter(lines: Iterable[str],
               reference: Optional[datetime] = None) -> Iterator[AuthEvent]:
    """Stream parser; useful for very large log files."""
    for line in lines:
        ev = parse_line(line, reference)
        if ev is not None:
            yield ev


def normalize_event(ev: AuthEvent) -> AuthEvent:
    """In-place normalisation. Lower-cases username and trims whitespace.

    Adds no new fields — kept for symmetry with the report's "log
    normalisation" stage so callers can chain it explicitly.
    """
    if ev.user is not None:
        ev.user = ev.user.strip().lower() or None
    if ev.ip is not None:
        ev.ip = ev.ip.strip() or None
    return ev
