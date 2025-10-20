#!/usr/bin/env python3
"""Interactive real-time dashboard for SysView.

The original ``sysview.py`` script already provides a curses based
histogram view, but it is primarily optimised for power users that are
comfortable with the keyboard driven interface.  This module offers an
alternative dashboard that emphasises discoverability and quick
inspection of syscall activity and CPU usage per process.  It reuses the
``SyscallMonitor`` component so it can run on top of the existing eBPF
collector, and provides:

* colour coded bar charts for syscall rates;
* live CPU utilisation for the most active processes;
* interactive filtering of syscall categories.

The dashboard intentionally keeps the rendering code separate from the
data collection helpers so that the latter can be unit tested without a
real terminal session.  The UI itself is still implemented with curses
to avoid introducing heavy third-party dependencies while keeping the
runtime footprint small.
"""

from __future__ import annotations

import argparse
import curses
import signal
import time
from collections import deque
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Set

from sysview import SyscallConfig, SyscallMonitor


# ────────────────────────────── helpers ──────────────────────────────


def _read_proc_comm(pid: int) -> str:
    """Return the process name for ``pid``.

    The helper is tiny but isolated to make it easier to mock in unit
    tests.  ``proc`` files disappear once a process exits; therefore
    errors are silently ignored and an informative fallback is returned.
    """

    try:
        with open(f"/proc/{pid}/comm", "r", encoding="utf-8") as comm_file:
            name = comm_file.read().strip()
            return name or f"pid {pid}"
    except OSError:
        return f"pid {pid}"


class CategoryFilter:
    """Track which syscall categories are visible in the dashboard."""

    def __init__(self, categories: Sequence[str]):
        self._categories: List[str] = list(categories)
        self._active: Set[str] = set(self._categories)

    @property
    def categories(self) -> Sequence[str]:
        return list(self._categories)

    @property
    def active(self) -> Set[str]:
        return set(self._active)

    def toggle(self, category: str) -> None:
        if category not in self._categories:
            return

        if category in self._active:
            if len(self._active) == 1:
                # Always keep at least one category visible to avoid an
                # empty dashboard.  Toggling the last active category
                # simply resets the filter back to "show all".
                self._active = set(self._categories)
            else:
                self._active.remove(category)
        else:
            self._active.add(category)

    def is_enabled(self, category: Optional[str]) -> bool:
        if not self._active:
            return True
        if category is None:
            return True
        return category in self._active


class ProcessCpuCollector:
    """Collect per-process CPU utilisation from ``/proc``.

    The collector keeps track of cumulative jiffies for the whole system
    and for each observed process.  Successive samples are converted to
    percentage values.  The logic is based on the standard
    ``/proc/stat``/``/proc/<pid>/stat`` layout which is available on all
    kernels that support eBPF.
    """

    def __init__(self):
        self._last_total: Optional[int] = None
        self._last_proc: Dict[int, int] = {}

    # The next two methods are deliberately tiny wrappers so that unit
    # tests can patch them easily without touching ``open`` globally.
    def _read_total_jiffies(self) -> int:
        with open("/proc/stat", "r", encoding="utf-8") as stat_file:
            first_line = stat_file.readline()
        parts = first_line.split()
        if not parts or parts[0] != "cpu":
            raise RuntimeError("/proc/stat is missing the aggregate cpu line")
        return sum(int(value) for value in parts[1:])

    def _read_proc_jiffies(self, pid: int) -> Optional[int]:
        try:
            with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as stat_file:
                contents = stat_file.readline()
        except OSError:
            return None

        parts = contents.split()
        if len(parts) < 17:
            return None
        # utime is field 14, stime is field 15 (0-indexed 13/14)
        utime = int(parts[13])
        stime = int(parts[14])
        return utime + stime

    def sample(self, pids: Iterable[int]) -> Dict[int, float]:
        """Return CPU percentages for ``pids`` based on deltas."""

        snapshot: Dict[int, float] = {pid: 0.0 for pid in pids}
        pids = list(snapshot.keys())
        if not pids:
            return snapshot

        total = self._read_total_jiffies()
        proc_totals: Dict[int, int] = {}
        for pid in pids:
            proc_total = self._read_proc_jiffies(pid)
            if proc_total is not None:
                proc_totals[pid] = proc_total

        if self._last_total is None:
            self._last_total = total
            self._last_proc = proc_totals
            return snapshot

        delta_total = max(1, total - self._last_total)

        for pid, current in proc_totals.items():
            previous = self._last_proc.get(pid)
            if previous is None or current < previous:
                continue
            delta_proc = current - previous
            snapshot[pid] = (delta_proc / delta_total) * 100.0

        # update history after computing deltas so the same sample isn't
        # processed twice.
        self._last_total = total
        self._last_proc = proc_totals

        return snapshot


@dataclass
class SyscallBar:
    name: str
    rate: float
    color: int
    category: str
    history: deque


class DashboardView:
    """Render syscall and CPU statistics using curses."""

    BAR_CHAR = "█"

    def __init__(
        self,
        monitor: SyscallMonitor,
        category_filter: CategoryFilter,
        cpu_collector: ProcessCpuCollector,
    ) -> None:
        self.monitor = monitor
        self.category_filter = category_filter
        self.cpu_collector = cpu_collector
        self._running = True

    # ────────────── initialisation helpers ──────────────

    def _prepare_curses(self, screen: "curses._CursesWindow") -> None:
        curses.curs_set(0)
        screen.nodelay(True)
        curses.start_color()
        curses.use_default_colors()
        for syscall in self.monitor.syscalls:
            color_index = syscall["color"]
            color_def = syscall.get("color_def", curses.COLOR_WHITE)
            try:
                curses.init_pair(color_index, color_def, -1)
            except curses.error:
                # Terminals with a limited colour palette can raise an
                # exception when reusing a colour pair.  Falling back to
                # the default keeps the UI functional.
                curses.init_pair(color_index, -1, -1)

    # ────────────── UI helpers ──────────────

    def _gather_syscall_bars(
        self, current_rates: Dict[str, float]
    ) -> List[SyscallBar]:
        bars: List[SyscallBar] = []
        for syscall in self.monitor.syscalls:
            category = syscall.get("category")
            if not self.category_filter.is_enabled(category):
                continue
            name = syscall["name"]
            bars.append(
                SyscallBar(
                    name=name,
                    rate=current_rates.get(name, 0.0),
                    color=syscall["color"],
                    category=category or "uncategorised",
                    history=self.monitor.history[name],
                )
            )
        bars.sort(key=lambda bar: bar.rate, reverse=True)
        return bars

    def _draw_header(self, screen: "curses._CursesWindow", width: int) -> None:
        runtime = self.monitor.get_runtime()
        title = (
            f" SysView Dashboard — interval {self.monitor.sample_interval:.2f}s, "
            f"history {self.monitor.history_size} samples, "
            f"runtime {runtime:,.1f}s "
        )
        screen.addstr(0, 0, title[: width - 1], curses.A_BOLD)

    def _draw_categories(self, screen: "curses._CursesWindow", row: int, width: int) -> int:
        parts = [
            "Categories (press the highlighted key to toggle):",
        ]
        key_mapping = self._key_mapping()
        for key, category in key_mapping:
            active = category in self.category_filter.active
            marker = "●" if active else "○"
            parts.append(f" [{key}] {category} {marker}")
        line = "".join(parts)
        screen.addstr(row, 0, line[: width - 1], curses.A_DIM)
        return row + 1

    def _key_mapping(self) -> List[tuple[str, str]]:
        mapping: List[tuple[str, str]] = []
        for idx, category in enumerate(self.category_filter.categories, start=1):
            if idx <= 9:
                mapping.append((str(idx), category))
            else:
                mapping.append((chr(ord("a") + idx - 10), category))
        return mapping

    def _draw_syscall_bars(
        self,
        screen: "curses._CursesWindow",
        start_row: int,
        width: int,
        bars: Sequence[SyscallBar],
    ) -> int:
        if not bars:
            screen.addstr(start_row, 0, "No syscalls match the current filter", curses.A_DIM)
            return start_row + 2

        max_rate = max((bar.rate for bar in bars), default=1.0) or 1.0
        bar_space = max(10, width - 30)
        row = start_row
        for bar in bars:
            meter_len = int((bar.rate / max_rate) * bar_space) if max_rate else 0
            meter = self.BAR_CHAR * meter_len
            label = f"{bar.name:<16} {bar.rate:8.1f}/s  {bar.category:<16}"
            screen.addstr(row, 0, label[: width - 1], curses.color_pair(bar.color) | curses.A_BOLD)
            row += 1
            if meter:
                screen.addstr(row, 4, meter[: width - 5], curses.color_pair(bar.color))
            row += 1
            history_line = self._history_line(bar.history, bar_space)
            screen.addstr(row, 4, history_line[: width - 5], curses.A_DIM)
            row += 2
            if row >= curses.LINES - 6:
                break
        return row

    def _history_line(self, history: deque, width: int) -> str:
        if not history:
            return ""
        values = list(history)[-width:]
        if not values:
            return ""
        max_value = max(values) or 1.0
        blocks = "▁▂▃▄▅▆▇█"
        output = []
        for value in values:
            idx = int((value / max_value) * (len(blocks) - 1)) if max_value else 0
            output.append(blocks[idx])
        return "".join(output)

    def _draw_cpu_usage(
        self,
        screen: "curses._CursesWindow",
        start_row: int,
        width: int,
        cpu_usage: Dict[int, float],
    ) -> None:
        row = start_row
        screen.addstr(row, 0, "Top process CPU usage:", curses.A_BOLD)
        row += 1
        if not cpu_usage:
            screen.addstr(row, 0, "(no process information yet)", curses.A_DIM)
            return

        items = sorted(cpu_usage.items(), key=lambda kv: kv[1], reverse=True)
        for pid, percent in items[:5]:
            proc_name = _read_proc_comm(pid)
            line = f"  {pid:>6d}  {percent:5.1f}%  {proc_name}"
            screen.addstr(row, 0, line[: width - 1])
            row += 1

    def _draw_footer(self, screen: "curses._CursesWindow", height: int) -> None:
        footer = "Commands: q quit | space pause/resume | +/- history | </> interval"
        screen.addstr(height - 1, 0, footer[: curses.COLS - 1], curses.A_DIM)

    # ────────────── public API ──────────────

    def run(self, screen: "curses._CursesWindow") -> None:
        self._prepare_curses(screen)
        paused = False

        def handle_sigint(signum, frame):
            self._running = False

        signal.signal(signal.SIGINT, handle_sigint)

        while self._running:
            start = time.time()

            if not paused:
                current_rates = self.monitor.update_counts()
            else:
                current_rates = {name: self.monitor.history[name][-1] for name in self.monitor.history}

            pids = set()
            for counts in self.monitor.entity_counts.values():
                for entity_id in counts:
                    pid, _tid = self.monitor.entity_id_to_components(entity_id)
                    pids.add(pid)
            cpu_usage = self.cpu_collector.sample(pids)

            screen.erase()
            height, width = screen.getmaxyx()
            self._draw_header(screen, width)
            row = 2
            row = self._draw_categories(screen, row, width)
            bars = self._gather_syscall_bars(current_rates)
            row = self._draw_syscall_bars(screen, row + 1, width, bars)
            self._draw_cpu_usage(screen, max(row + 1, height - 8), width, cpu_usage)
            self._draw_footer(screen, height)
            screen.refresh()

            delay = max(0.05, self.monitor.sample_interval - (time.time() - start))
            for _ in range(int(delay / 0.05)):
                ch = screen.getch()
                if ch == -1:
                    time.sleep(0.05)
                    continue
                if ch in (ord("q"), ord("Q")):
                    self._running = False
                    break
                if ch in (ord("+"), ord("=")):
                    self.monitor.adjust_history_size(5)
                elif ch == ord("-"):
                    self.monitor.adjust_history_size(-5)
                elif ch == ord("<"):
                    self.monitor.adjust_sample_interval(-0.1)
                elif ch == ord(">"):
                    self.monitor.adjust_sample_interval(0.1)
                elif ch in (ord(" "), ord("p"), ord("P")):
                    paused = not paused
                else:
                    key_mapping = dict(self._key_mapping())
                    key = chr(ch) if 32 <= ch < 127 else None
                    if key and key in key_mapping:
                        self.category_filter.toggle(key_mapping[key])


# ────────────────────────────── CLI ────────────────────────────────


def parse_args(argv: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Graphical dashboard for SysView")
    parser.add_argument("--config", "-c", help="Path to syscall configuration JSON")
    parser.add_argument(
        "--interval",
        "-i",
        type=float,
        default=1.0,
        help="Sampling interval in seconds",
    )
    parser.add_argument(
        "--history",
        "-H",
        type=int,
        default=60,
        help="Number of samples kept in history",
    )
    parser.add_argument(
        "--group-by",
        choices=["pid", "tid"],
        default="pid",
        help="How to group syscall counts",
    )
    return parser.parse_args(argv)


def load_config(path: Optional[str]) -> SyscallConfig:
    if path:
        return SyscallConfig(filename=path)
    return SyscallConfig()


def run_dashboard(args: argparse.Namespace) -> None:
    config = load_config(args.config)
    monitor = SyscallMonitor(
        config=config,
        interval=args.interval,
        history_size=args.history,
        group_by=args.group_by,
    )

    categories = list(config.categories.keys()) if hasattr(config, "categories") else []
    if not categories:
        categories = sorted(
            {syscall.get("category", "uncategorised") for syscall in config.get_enabled_syscalls().values()}
        )

    category_filter = CategoryFilter(categories)
    cpu_collector = ProcessCpuCollector()
    view = DashboardView(monitor, category_filter, cpu_collector)

    curses.wrapper(view.run)


def main(argv: Optional[Sequence[str]] = None) -> None:
    args = parse_args(argv)
    run_dashboard(args)


if __name__ == "__main__":
    main()

