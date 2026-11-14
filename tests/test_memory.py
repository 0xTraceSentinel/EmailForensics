import pytest

from emailforensics.memory import MB, Guard, MemoryPressure, Snapshot, available


def guard(values, **kw):
    seq = iter(values)
    last = [values[-1]]

    def probe():
        try:
            last[0] = next(seq)
        except StopIteration:
            pass
        return Snapshot(last[0] * MB, None)

    return Guard(min_free_mb=1000, probe=probe, sleep=lambda s: None, interval=0, **kw)


def test_plenty_of_memory_is_not_pressure():
    g = guard([8000])
    assert g.check() is False and g.pressure is False and g.events == 0


def test_low_memory_shrinks_batches_without_stopping():
    g = guard([1500, 1500])
    assert g.check() is True and g.pressure is True and g.events == 1
    assert guard([1500, 3000]).check() is False


def test_critical_memory_waits_then_recovers():
    g = guard([500, 500, 500, 2500])
    assert g.check() is True


def test_critical_memory_that_persists_stops_cleanly():
    g = guard([400], wait_s=10)
    with pytest.raises(MemoryPressure, match="400 MB"):
        g.check()


def test_fits_and_disabled_guard():
    g = guard([3000])
    assert g.fits(1000 * MB) and not g.fits(2500 * MB)
    off = Guard(min_free_mb=0, probe=lambda: Snapshot(1, 1))
    assert off.check() is False and off.fits(10**12)


def test_commit_limit_counts_as_free_memory():
    assert Snapshot(8000, 300).lowest == 300 and Snapshot(None, None).lowest is None


def test_probe_reads_this_machine():
    snap = available()
    assert snap.lowest is None or snap.lowest > 0
