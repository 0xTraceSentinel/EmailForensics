from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from statistics import median

from emailforensics.analysis.config import Settings


@dataclass
class Week:
    week_start: date
    days: int
    messages: int
    median_first_min: int
    median_last_min: int
    day_firsts: list[int] = field(default_factory=list, repr=False)
    baseline_min: int | None = None
    shift_min: int | None = None
    agreement: float | None = None
    place: str | None = None


def _minutes(t: datetime, boundary: int) -> int:
    return (t.hour * 60 + t.minute - boundary) % 1440 + boundary


def weekly(times: list[datetime], settings: Settings, base: str | None) -> list[Week]:
    cfg = settings.sendtime
    boundary = -int(cfg["day_boundary_offset_min"])
    days: dict[date, list[int]] = defaultdict(list)
    for t in times:
        days[(t - timedelta(minutes=boundary)).date()].append(_minutes(t, boundary))
    by_week: dict[date, list[tuple[int, int, int]]] = defaultdict(list)
    for d, mins in days.items():
        by_week[d - timedelta(days=d.weekday())].append((min(mins), max(mins), len(mins)))
    weeks = [
        Week(
            week_start=ws,
            days=len(rows),
            messages=sum(r[2] for r in rows),
            median_first_min=int(median(r[0] for r in rows)),
            median_last_min=int(median(r[1] for r in rows)),
            day_firsts=sorted(r[0] for r in rows),
        )
        for ws, rows in sorted(by_week.items())
    ]
    usable = [w for w in weeks if w.days >= cfg["min_days"]]
    span = timedelta(weeks=int(cfg.get("baseline_weeks", 13)))
    tol = cfg["tolerance_min"]
    need = float(cfg.get("min_day_agreement", 0.6))
    base_offsets = settings.places[base].offsets if base and base in settings.places else []
    expected: list[tuple[str | None, int]] = [(base, 0)]
    for code, p in settings.places.items():
        if code != base and base_offsets:
            expected += [(code, -(po - bo)) for po in p.offsets for bo in base_offsets]
    for w in usable:
        neighbours = [x.median_first_min for x in usable if x is not w and abs(x.week_start - w.week_start) <= span]
        if len(neighbours) < 4:
            continue
        w.baseline_min = int(median(neighbours))
        w.shift_min = w.median_first_min - w.baseline_min
        for code, delta in expected:
            if abs(w.shift_min - delta) > tol:
                continue
            agree = sum(1 for f in w.day_firsts if abs(f - w.baseline_min - delta) <= tol) / w.days
            w.agreement = round(agree, 2)
            if agree >= need:
                w.place = code
            break
    return weeks


def calibrate(weeks: list[Week], offsets: list[tuple[datetime, str]], settings: Settings) -> dict:
    cfg = settings.sendtime
    by_week: dict[date, list[str]] = defaultdict(list)
    for t, place in offsets:
        d = t.date()
        by_week[d - timedelta(days=d.weekday())].append(place)
    checked = agree = 0
    confusion: dict[str, int] = defaultdict(int)
    for w in weeks:
        places = by_week.get(w.week_start)
        if not w.place or not places or len(places) < int(cfg.get("calibration_min_messages", 3)):
            continue
        dominant = max(set(places), key=places.count)
        checked += 1
        agree += dominant == w.place
        confusion[f"{w.place}->{dominant}"] += 1
    rate = round(agree / checked, 2) if checked else None
    reliable = checked >= int(cfg.get("calibration_min_weeks", 5)) and rate is not None and rate >= float(cfg.get("calibration_min_agreement", 0.8))
    return {"weeks_checked": checked, "agreement": rate, "reliable": reliable, "label_vs_offsets": dict(confusion)}
