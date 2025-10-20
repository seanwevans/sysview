import pytest

from dashboard import CategoryFilter, ProcessCpuCollector, parse_args


def test_category_filter_toggle():
    filt = CategoryFilter(["file", "network", "memory"])
    assert filt.is_enabled("file")

    filt.toggle("file")
    assert not filt.is_enabled("file")
    assert filt.is_enabled("network")

    # toggling the last active category restores them all
    filt.toggle("network")
    filt.toggle("memory")
    assert filt.is_enabled("file")
    assert filt.is_enabled("network")
    assert filt.is_enabled("memory")


def test_process_cpu_collector_first_sample_returns_zero(monkeypatch):
    collector = ProcessCpuCollector()

    totals = iter([100])
    monkeypatch.setattr(
        collector,
        "_read_total_jiffies",
        lambda: next(totals),
    )
    monkeypatch.setattr(
        collector,
        "_read_proc_jiffies",
        lambda pid: 10,
    )

    snapshot = collector.sample([1234])
    assert snapshot == {1234: 0.0}


def test_process_cpu_collector_computes_percentage(monkeypatch):
    collector = ProcessCpuCollector()

    total_values = iter([1000, 1200])
    monkeypatch.setattr(collector, "_read_total_jiffies", lambda: next(total_values))

    proc_values = {
        100: iter([100, 140]),
    }

    def fake_proc(pid):
        return next(proc_values[pid])

    monkeypatch.setattr(collector, "_read_proc_jiffies", fake_proc)

    # first sample initialises baseline
    collector.sample([100])
    # second sample should compute the delta: (40 / 200) * 100 = 20%
    snapshot = collector.sample([100])
    assert snapshot == pytest.approx({100: 20.0})


def test_parse_args_defaults():
    args = parse_args([])
    assert args.interval == pytest.approx(1.0)
    assert args.history == 60
    assert args.group_by == "pid"

