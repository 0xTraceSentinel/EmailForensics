from __future__ import annotations

import ctypes
import gc
import os
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass

MB = 1 << 20
DEFAULT_MIN_FREE_MB = 1024
DEFAULT_LOW_FACTOR = 2


class MemoryPressure(RuntimeError):
    pass


@dataclass
class Snapshot:
    physical: int | None
    commit: int | None

    @property
    def lowest(self) -> int | None:
        known = [v for v in (self.physical, self.commit) if v is not None]
        return min(known) if known else None


class _MemoryStatusEx(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_ulong),
        ("dwMemoryLoad", ctypes.c_ulong),
        ("ullTotalPhys", ctypes.c_ulonglong),
        ("ullAvailPhys", ctypes.c_ulonglong),
        ("ullTotalPageFile", ctypes.c_ulonglong),
        ("ullAvailPageFile", ctypes.c_ulonglong),
        ("ullTotalVirtual", ctypes.c_ulonglong),
        ("ullAvailVirtual", ctypes.c_ulonglong),
        ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
    ]


def available() -> Snapshot:
    if sys.platform == "win32":
        status = _MemoryStatusEx()
        status.dwLength = ctypes.sizeof(_MemoryStatusEx)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return Snapshot(int(status.ullAvailPhys), int(status.ullAvailPageFile))
        return Snapshot(None, None)
    try:
        with open("/proc/meminfo", encoding="ascii") as f:
            info = {line.split(":")[0]: int(line.split()[1]) * 1024 for line in f if line.split()[1:2]}
    except (OSError, ValueError, IndexError):
        return Snapshot(None, None)
    return Snapshot(info.get("MemAvailable"), None)


def min_free_mb(option: int | None = None) -> int:
    if option is not None:
        return option
    try:
        return int(os.environ.get("EMAILFORENSICS_MIN_FREE_MB", DEFAULT_MIN_FREE_MB))
    except ValueError:
        return DEFAULT_MIN_FREE_MB


class Guard:
    def __init__(
        self,
        min_free_mb: int = DEFAULT_MIN_FREE_MB,
        log: Callable[[str], None] = lambda s: None,
        probe: Callable[[], Snapshot] = available,
        sleep: Callable[[float], None] = time.sleep,
        interval: float = 1.0,
        wait_s: float = 60.0,
    ) -> None:
        self.critical = min_free_mb * MB
        self.low = self.critical * DEFAULT_LOW_FACTOR
        self.log, self.probe, self.sleep = log, probe, sleep
        self.interval, self.wait_s = interval, wait_s
        self.pressure = False
        self.events = 0
        self._last = 0.0

    def free(self) -> int | None:
        return self.probe().lowest

    def check(self, force: bool = False) -> bool:
        if not self.critical:
            return False
        now = time.monotonic()
        if not force and now - self._last < self.interval:
            return self.pressure
        self._last = now
        free = self.free()
        if free is None or free >= self.low:
            self.pressure = False
            return False
        gc.collect()
        free = self.free()
        if free is None or free >= self.low:
            self.pressure = False
            return False
        if not self.pressure:
            self.events += 1
            self.log(f"memory low ({free // MB:,} MB free): smaller batches until it recovers")
        self.pressure = True
        if free >= self.critical:
            return True
        waited = 0.0
        while waited < self.wait_s:
            self.sleep(2.0)
            waited += 2.0
            gc.collect()
            free = self.free()
            if free is None or free >= self.critical:
                self.log(f"memory recovered to {(free or 0) // MB:,} MB free; continuing")
                return True
        raise MemoryPressure(
            f"only {free // MB:,} MB of memory free (minimum {self.critical // MB:,} MB) after waiting {int(self.wait_s)} s"
        )

    def fits(self, needed_bytes: int) -> bool:
        if not self.critical:
            return True
        free = self.free()
        return free is None or free - needed_bytes >= self.critical


NO_GUARD = Guard(min_free_mb=0)
