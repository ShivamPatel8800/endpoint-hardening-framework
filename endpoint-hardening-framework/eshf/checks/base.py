"""Check data model and the operator/comparison engine."""
import re
from dataclasses import dataclass
from enum import Enum


class Status(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARN = "WARN"
    ERROR = "ERROR"
    SKIP = "SKIP"


@dataclass
class CheckResult:
    check_id: str
    title: str
    category: str
    severity: str
    status: Status
    actual: str = ""
    message: str = ""
    remediation: str = ""


def _norm(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value).strip()


def _as_number(value):
    try:
        return float(_norm(value).replace(",", ""))
    except (TypeError, ValueError):
        return None


def compare(actual, operator, expected):
    """Generic comparison. Returns (passed: bool, human_readable_detail: str)."""
    exp_txt = expected if isinstance(expected, str) else repr(expected)

    if isinstance(expected, bool):
        actual_bool = _norm(actual).lower() in ("1", "true", "yes", "on", "enabled")
        return actual_bool == expected, f"actual={_norm(actual)!r} expected={expected}"

    if operator == "eq":
        ok = _norm(actual).lower() == _norm(expected).lower()
    elif operator == "ne":
        ok = _norm(actual).lower() != _norm(expected).lower()
    elif operator in ("gt", "ge", "lt", "le"):
        a, b = _as_number(actual), _as_number(expected)
        if a is None or b is None:
            return False, f"non-numeric comparison: actual={actual!r} expected={expected!r}"
        ok = {"gt": a > b, "ge": a >= b, "lt": a < b, "le": a <= b}[operator]
    elif operator == "contains":
        ok = _norm(expected).lower() in _norm(actual).lower()
    elif operator == "not_contains":
        ok = _norm(expected).lower() not in _norm(actual).lower()
    elif operator == "regex":
        ok = re.search(str(expected), _norm(actual)) is not None
    elif operator == "in":
        options = expected if isinstance(expected, list) else str(expected).split("|")
        ok = _norm(actual).lower() in {_norm(v).lower() for v in options}
    elif operator == "not_in":
        options = expected if isinstance(expected, list) else str(expected).split("|")
        ok = _norm(actual).lower() not in {_norm(v).lower() for v in options}
    elif operator == "present":
        ok = actual is not None and _norm(actual) != ""
    elif operator == "absent":
        ok = actual is None or _norm(actual) == ""
    else:
        return False, f"unknown operator {operator!r}"

    return ok, f"actual={_norm(actual)!r} {operator} expected={exp_txt!r}"
