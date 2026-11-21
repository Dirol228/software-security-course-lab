"""Детектор аномалій варіанта 19: А4 — різке зростання обсягу зчитаних даних;
А2 — доступ поза типовим часовим вікном. Усі пороги — параметри."""
from __future__ import annotations

import collections
from datetime import datetime, timezone

from accesscontrol.monitor import AnomalyDetector, AuditLog, Permission


def _to_dt(ts, tz=None) -> datetime:
    """ts може бути datetime, epoch-секундами або рядком ISO-8601."""
    if isinstance(ts, datetime):
        return ts
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, tz)
    return datetime.fromisoformat(str(ts))


def _is_read(action) -> bool:
    if isinstance(action, Permission):
        return bool(action & Permission.READ)
    if isinstance(action, int):
        return bool(action & Permission.READ.value)
    return "READ" in str(action).upper()


class VariantDetector(AnomalyDetector):
    def __init__(self, work_start: int = 8, work_end: int = 20, min_offhours: int = 3,
                 bucket_seconds: int = 3600, burst_factor: float = 3.0,
                 min_burst_reads: int = 10, tz=None) -> None:
        self.work_start, self.work_end = work_start, work_end
        self.min_offhours = min_offhours
        self.bucket_seconds = bucket_seconds
        self.burst_factor = burst_factor
        self.min_burst_reads = min_burst_reads
        self.tz = tz

    def scan(self, log: AuditLog) -> list[str]:
        entries = log.entries()
        return self._read_burst(entries) + self._off_hours(entries)

    # --- А4: різке зростання обсягу зчитаних даних ---
    def _read_burst(self, entries) -> list[str]:
        per_subject: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
        for e in entries:
            if e["allowed"] and _is_read(e["action"]):
                t = _to_dt(e["ts"], self.tz).timestamp()
                per_subject[e["subject"]][int(t // self.bucket_seconds)] += 1
        alerts = []
        for subject, buckets in sorted(per_subject.items()):
            first, last = min(buckets), max(buckets)
            counts = [buckets.get(b, 0) for b in range(first, last + 1)]   # порожні вікна = 0
            for i in range(1, len(counts)):
                baseline = sum(counts[:i]) / i
                if counts[i] >= self.min_burst_reads and counts[i] > self.burst_factor * max(baseline, 1.0):
                    alerts.append(f"А4: {subject} — сплеск читань: {counts[i]} за вікно "
                                  f"{self.bucket_seconds}с (базовий рівень {baseline:.1f}, "
                                  f"поріг ×{self.burst_factor}, не менше {self.min_burst_reads})")
                    break
        return alerts

    # --- А2: доступ поза типовим часовим вікном ---
    def _in_window(self, hour: int) -> bool:
        if self.work_start <= self.work_end:
            return self.work_start <= hour < self.work_end
        return hour >= self.work_start or hour < self.work_end     # вікно через північ

    def _off_hours(self, entries) -> list[str]:
        counter: collections.Counter = collections.Counter()
        for e in entries:
            if not self._in_window(_to_dt(e["ts"], self.tz).hour):
                counter[e["subject"]] += 1
        return [f"А2: {s} — {n} звернень поза вікном {self.work_start:02d}:00–{self.work_end:02d}:00 "
                f"(поріг {self.min_offhours})"
                for s, n in sorted(counter.items()) if n >= self.min_offhours]
