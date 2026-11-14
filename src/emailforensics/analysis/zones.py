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
    def __init__(self, places: dict[str, tuple[tuple[str, ...], tuple[int, ...]]], sample: int = 8,
                 utc_reference: tuple[str, ...] = ()) -> None:
        self.places = places
        self.sample = sample
        self.configured = {z for zones, _ in places.values() for z in zones}
        world = _world()
        self.own = {c for z, c in world if z in self.configured and c}
        self.others = tuple((z, c) for z, c in world if z not in self.configured and not (c and c in self.own))
        self.utc_reference = tuple(z for z in utc_reference if _zone(z) is not None)
        self._full: dict[tuple[int, datetime], OffsetMatch] = {}
        self._local: dict[tuple[int, datetime], tuple[tuple[str, ...], tuple[str, ...]]] = {}

    @staticmethod
    def _hour(when: date | datetime) -> datetime:
        if isinstance(when, datetime):
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            return when.astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
        return datetime.combine(when, time(12), tzinfo=timezone.utc)

    def _places_at(self, minutes: int, at: datetime) -> tuple[tuple[str, ...], tuple[str, ...]]:
        key = (minutes, at)
        hit = self._local.get(key)
        if hit is None:
            hits, zones = [], []
            for code, (pzones, offsets) in self.places.items():
                if pzones:
                    matched = [z for z in pzones if offset_at(z, at) == minutes]
                    if matched:
                        hits.append(code)
                        zones += matched
                elif minutes in offsets:
                    hits.append(code)
            hit = self._local[key] = (tuple(hits), tuple(zones))
        return hit

    def match(self, minutes: int, when: date | datetime) -> OffsetMatch:
        at = self._hour(when)
        key = (minutes, at)
        hit = self._full.get(key)
        if hit is None:
            places, zones = self._places_at(minutes, at)
            others = sorted({country_name(c) if c else z for z, c in self.others if offset_at(z, at) == minutes})
            hit = self._full[key] = OffsetMatch(places, zones, tuple(others[: self.sample]), len(others))
        return hit

    def any_place_at(self, minutes: int, when: date | datetime) -> bool:
        return bool(self._places_at(minutes, self._hour(when))[0])

    def utc_is_local_at(self, when: date | datetime) -> bool:
        at = self._hour(when)
        return bool(self._places_at(0, at)[0]) or any(offset_at(z, at) == 0 for z in self.utc_reference)
