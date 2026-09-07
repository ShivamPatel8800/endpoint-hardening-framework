"""Scan orchestration, scoring, and the report model."""
import datetime
import platform
import socket
import time
from collections import Counter

from ..checks.base import Status
from ..checks.builtin import run_check

WEIGHTS = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}


class ScanReport:
    def __init__(self, baseline_name, target, results, duration):
        self.baseline_name = baseline_name
        self.target = target
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.duration = duration
        self.results = results

    @property
    def summary(self):
        c = Counter(r.status.value for r in self.results)
        return {
            "total": len(self.results),
            "passed": c.get("PASS", 0), "failed": c.get("FAIL", 0),
            "warnings": c.get("WARN", 0), "errors": c.get("ERROR", 0),
            "skipped": c.get("SKIP", 0),
            "score": self.score(), "grade": self.grade(),
            "by_severity": dict(Counter(r.severity for r in self.results)),
        }

    def score(self):
        """Severity-weighted compliance score over completed checks (0-100).
        SKIP/WARN/ERROR checks are excluded so cross-platform noise is free."""
        total = passed = 0
        for r in self.results:
            if r.status not in (Status.PASS, Status.FAIL):
                continue
            w = WEIGHTS.get(r.severity, 1)
            total += w
            if r.status == Status.PASS:
                passed += w
        return round(100 * passed / total) if total else 100

    def grade(self):
        s = self.score()
        return "A" if s >= 90 else "B" if s >= 80 else "C" if s >= 70 else "D" if s >= 60 else "F"


def run_scan(checks, baseline_meta=None):
    meta = baseline_meta or {}
    start = time.monotonic()
    results = [run_check(c) for c in checks]
    duration = time.monotonic() - start
    target = f"{socket.gethostname()} ({platform.system()} {platform.release()}, {platform.machine()})"
    return ScanReport(meta.get("name", "unnamed baseline"), target, results, duration)
