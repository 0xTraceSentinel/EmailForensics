from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime, time, timezone
from functools import lru_cache
from importlib import metadata
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones

_REGIONS = ("Africa/", "America/", "Asia/", "Atlantic/", "Australia/", "Europe/", "Indian/", "Pacific/")


def tzdata_version() -> str:
    try:
        return metadata.version("tzdata")
    except metadata.PackageNotFoundError:
        return "system"


@lru_cache(maxsize=None)
def _zone(name: str) -> ZoneInfo | None:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError):
        return None


def _tab(name: str) -> list[list[str]]:
    try:
        from importlib import resources

        text = resources.files("tzdata").joinpath("zoneinfo", name).read_text(encoding="utf-8")
    except (ModuleNotFoundError, FileNotFoundError, OSError):
        return []
    return [line.split("	") for line in text.splitlines() if line and not line.startswith("#")]


@lru_cache(maxsize=1)
def _countries() -> dict[str, str]:
    return {row[0]: row[1] for row in _tab("iso3166.tab") if len(row) >= 2}


@lru_cache(maxsize=1)
def _world() -> tuple[tuple[str, str], ...]:
    rows = [(row[2], row[0]) for row in _tab("zone.tab") if len(row) >= 3]
    if not rows:
        rows = [(z, "") for z in available_timezones() if z.startswith(_REGIONS)]
    return tuple(sorted((z, c) for z, c in rows if c != "AQ" and _zone(z) is not None))


def country_name(code: str) -> str:
    return _countries().get(code, code)


def offset_at(name: str, at: datetime) -> int | None:
    z = _zone(name)
    if z is None:
        return None
    off = at.astimezone(z).utcoffset()
    return int(off.total_seconds() // 60) if off is not None else None


@dataclass(frozen=True)
class OffsetMatch:
    places: tuple[str, ...]
    zones: tuple[str, ...]
    alternatives: tuple[str, ...]
    alternative_count: int

    def json(self) -> dict:
        return {
            "places": list(self.places),
            "zones": list(self.zones),
            "also_consistent_with": list(self.alternatives),
            "also_consistent_count": self.alternative_count,
        }


class ZoneIndex:
    def __init__(self, places: dict[str, tuple[tuple[str, ...], tuple[int, ...]]], sample: int = 8) -> None:
        self.places = places
        self.sample = sample
        self.configured = {z for zones, _ in places.values() for z in zones}

    def match(self, minutes: int, when: date | datetime) -> OffsetMatch:
        if isinstance(when, datetime):
            hour = when.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
        else:
            hour = datetime.combine(when, time(12), tzinfo=timezone.utc)
        return self._match(minutes, hour)

    @lru_cache(maxsize=262144)
    def _match(self, minutes: int, at: datetime) -> OffsetMatch:
        hits, zones = [], []
        for code, (pzones, offsets) in self.places.items():
            if pzones:
                matched = [z for z in pzones if offset_at(z, at) == minutes]
                if matched:
                    hits.append(code)
                    zones += matched
            elif minutes in offsets:
                hits.append(code)
        own = {c for z, c in _world() if z in self.configured}
        others = sorted({country_name(c) if c else z for z, c in _world()
                         if z not in self.configured and c not in own and offset_at(z, at) == minutes})
        return OffsetMatch(tuple(hits), tuple(zones), tuple(others[: self.sample]), len(others))

    def any_place_at(self, minutes: int, when: date | datetime) -> bool:
        return bool(self.match(minutes, when).places)
