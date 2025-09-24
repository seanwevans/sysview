#!/usr/bin/env python3

import argparse
import collections
import copy
import datetime
import json
import logging
import os
import time

from bcc import BPF
import curses


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SyscallConfig:
    def __init__(self, filename=None):
        # Default syscalls configuration
        self.default_syscalls = {
            "write": {
                "name": "write",
                "color": 1,
                "color_def": curses.COLOR_GREEN,
                "desc": "Writing to files/pipes",
                "enabled": True,
                "category": "file",
            },
            "read": {
                "name": "read",
                "color": 2,
                "color_def": curses.COLOR_CYAN,
                "desc": "Reading from files/pipes",
                "enabled": True,
                "category": "file",
            },
            "open": {
                "name": "open",
                "color": 3,
                "color_def": curses.COLOR_YELLOW,
                "desc": "Opening files",
                "enabled": True,
                "category": "file",
            },
            "close": {
                "name": "close",
                "color": 4,
                "color_def": curses.COLOR_RED,
                "desc": "Closing file descriptors",
                "enabled": True,
                "category": "file",
            },
            "mmap": {
                "name": "mmap",
                "color": 5,
                "color_def": curses.COLOR_MAGENTA,
                "desc": "Memory mapping",
                "enabled": True,
                "category": "memory",
            },
            "socket": {
                "name": "socket",
                "color": 6,
                "color_def": curses.COLOR_BLUE,
                "desc": "Network socket operations",
                "enabled": True,
                "category": "network",
            },
            "poll": {
                "name": "poll",
                "color": 7,
                "color_def": curses.COLOR_WHITE,
                "desc": "I/O event notifications (poll/select/epoll)",
                "enabled": True,
                "aliases": ["select", "epoll_wait"],
                "category": "file",
            },
            "futex": {
                "name": "futex",
                "color": 8,
                "color_def": 208,  # Orange
                "desc": "Fast user-space locking",
                "enabled": True,
                "category": "synchronization",
            },
            "execve": {
                "name": "execve",
                "color": 9,
                "color_def": 85,  # Teal
                "desc": "Execute programs",
                "enabled": True,
                "category": "process",
            },
        }

        self.syscalls = copy.deepcopy(self.default_syscalls)

        if filename and os.path.exists(filename):
            try:
                with open(filename, "r") as f:
                    user_config = json.load(f)
                    self.merge_config(user_config)
            except ValueError as e:
                raise ValueError(f"Invalid configuration file '{filename}': {e}")
            except Exception as e:
                print(f"Error loading config file: {e}")

    def merge_config(self, user_config):
        """Merge user configuration with defaults"""
        if not isinstance(user_config, dict):
            raise ValueError("Config must be a dictionary")

        syscalls = user_config.get("syscalls")
        if syscalls is None:
            return
        if not isinstance(syscalls, dict):
            raise ValueError("'syscalls' must be a dictionary")

        for syscall_name, syscall_config in syscalls.items():
            if not isinstance(syscall_config, dict):
                raise ValueError(
                    f"Configuration for syscall '{syscall_name}' must be a dictionary"
                )

            base_config = copy.deepcopy(self.syscalls.get(syscall_name, {}))
            merged_config = {**base_config, **syscall_config}
            if "name" not in merged_config:
                merged_config["name"] = syscall_name

            validated = self._validate_syscall_config(syscall_name, merged_config)
            self.syscalls[syscall_name] = validated

    def get_enabled_syscalls(self):
        """Return only enabled syscalls"""
        return {
            name: config
            for name, config in self.syscalls.items()
            if config.get("enabled", True)
        }

    def save_config(self, filename):
        """Save current configuration to file"""
        with open(filename, "w") as f:
            json.dump({"syscalls": self.syscalls}, f, indent=2)

    def _validate_syscall_config(self, syscall_name, config):
        required_fields = {
            "name": str,
            "color": int,
            "desc": str,
            "enabled": bool,
        }

        for field, expected_type in required_fields.items():
            if field not in config:
                raise ValueError(
                    f"Missing required field '{field}' for syscall '{syscall_name}'"
                )
            if not isinstance(config[field], expected_type):
                raise ValueError(
                    f"Field '{field}' for syscall '{syscall_name}' must be of type "
                    f"{expected_type.__name__}"
                )

        if "color_def" in config and not isinstance(config["color_def"], int):
            raise ValueError(
                f"Field 'color_def' for syscall '{syscall_name}' must be an integer"
            )

        if "aliases" in config:
            aliases = config["aliases"]
            if not isinstance(aliases, list) or not all(
                isinstance(alias, str) for alias in aliases
            ):
                raise ValueError(
                    f"Field 'aliases' for syscall '{syscall_name}' must be a list of strings"
                )

        category = config.get("category", "uncategorized")
        if not isinstance(category, str):
            raise ValueError(
                f"Field 'category' for syscall '{syscall_name}' must be a string"
            )
        config["category"] = category

        return config


class SyscallMonitor:
    def __init__(self, config, interval=1, history_size=60, group_by="pid"):
        self.config = config
        self.sample_interval = interval
        self.history_size = history_size
        self.start_time = time.time()
        self.group_by = group_by
        self.disabled_syscalls = {}
        self.initialize_data_structures()
        self.bpf_text = self.generate_bpf_program()
        self.b = BPF(text=self.bpf_text)
        self.attach_kprobes()

    def initialize_data_structures(self):
        """Initialize data structures for tracking syscalls"""
        self.syscalls = []
        self.history = {}
        self.last_counts = {}
        self.total_counts = {}
        self.peak_rates = {}
        self.entity_counts = {}

        for name, config in self.config.get_enabled_syscalls().items():
            self.syscalls.append(config)
            self.history[name] = collections.deque(
                [0] * self.history_size, maxlen=self.history_size
            )
            self.last_counts[name] = 0
            self.total_counts[name] = 0
            self.peak_rates[name] = 0
            self.entity_counts[name] = {}

    def generate_bpf_program(self):
        """Dynamically generate BPF program based on enabled syscalls"""
        bpf_header = """
        #include <uapi/linux/ptrace.h>

        // Define BPF maps to store counts for different syscalls
        """

        bpf_maps = ""
        bpf_functions = ""

        enabled_syscalls = self.config.get_enabled_syscalls()
        for name in enabled_syscalls:
            bpf_maps += f"BPF_HASH({name}_count, u64, u64);\n"

        for name, config in enabled_syscalls.items():
            if getattr(self, "group_by", "pid") == "pid":
                key_assign = "key = id >> 32;"
            else:
                key_assign = "key = id;"
            function_template = """
            // Track {name} syscalls
            int trace_{name}_entry(struct pt_regs *ctx) {{
                u64 id = bpf_get_current_pid_tgid();
                u64 key = 0;
                u64 init = 1;

                {key_assign}

                u64 *count = {name}_count.lookup(&key);
                if (count) {{
                    (*count)++;
                }} else {{
                    {name}_count.update(&key, &init);
                }}

                return 0;
            }}
            """
            bpf_functions += function_template.format(
                name=name, key_assign=key_assign
            )

        return bpf_header + bpf_maps + bpf_functions

    def adjust_sample_interval(self, delta):
        """Adjust the sampling interval by ``delta`` seconds."""

        new_interval = max(0.1, self.sample_interval + delta)
        # Avoid tiny floating point noise by rounding to two decimals
        self.sample_interval = round(new_interval, 2)

    def adjust_history_size(self, delta):
        """Adjust history depth and resize the stored histories."""

        new_size = int(max(1, self.history_size + delta))
        if new_size == self.history_size:
            return

        for name, history in self.history.items():
            existing = list(history)
            if new_size > len(existing):
                padding = [0] * (new_size - len(existing))
                new_values = padding + existing
            else:
                new_values = existing[-new_size:]
            self.history[name] = collections.deque(new_values, maxlen=new_size)

        self.history_size = new_size

    def disable_syscall(self, name, reason):
        """Disable a syscall from monitoring and log the reason."""
        logger.warning("Disabling syscall %s: %s", name, reason)
        self.disabled_syscalls[name] = reason

        if name in self.config.syscalls:
            self.config.syscalls[name]["enabled"] = False
            self.config.syscalls[name]["disabled_reason"] = reason

        self.history.pop(name, None)
        self.last_counts.pop(name, None)
        self.total_counts.pop(name, None)
        self.peak_rates.pop(name, None)
        self.syscalls = [s for s in self.syscalls if s["name"] != name]

    def attach_kprobes(self):
        """Attach kprobes for all enabled syscalls"""
        enabled_syscalls = self.config.get_enabled_syscalls()

        for name, config in enabled_syscalls.items():
            attached_events = []
            current_alias = None
            try:
                event_name = self.b.get_syscall_fnname(name)
                self.b.attach_kprobe(
                    event=event_name,
                    fn_name=f"trace_{name}_entry",
                )
                attached_events.append((event_name, f"trace_{name}_entry"))

                for alias in config.get("aliases", []):
                    current_alias = alias
                    alias_event = self.b.get_syscall_fnname(alias)
                    self.b.attach_kprobe(
                        event=alias_event,
                        fn_name=f"trace_{name}_entry",
                    )
                    attached_events.append((alias_event, f"trace_{name}_entry"))
                    current_alias = None

            except Exception as e:
                reason = (
                    f"Failed to attach alias {current_alias} for {name}: {e}"
                    if current_alias
                    else f"Failed to attach probe for {name}: {e}"
                )

                for event, fn_name in attached_events:
                    try:
                        self.b.detach_kprobe(event=event, fn_name=fn_name)
                    except Exception:
                        pass

                self.disable_syscall(name, reason)

    def get_counts(self, name):
        """Get current per-entity counts for a syscall"""
        count_map = self.b.get_table(f"{name}_count")
        counts: dict[int, int] = {}
        for k, v in count_map.items():
            counts[int(k.value)] = v.value
        return counts

    def entity_id_to_components(self, entity_id: int) -> tuple[int, int]:
        """Return (pid, tid) tuple derived from the entity identifier."""
        if self.group_by == "pid":
            return entity_id, entity_id
        pid = entity_id >> 32
        tid = entity_id & 0xFFFFFFFF
        return pid, tid

    def format_entity_label(self, entity_id: int) -> str:
        """Generate a human-friendly label for a workload."""
        pid, tid = self.entity_id_to_components(entity_id)

        if self.group_by == "pid":
            comm_path = f"/proc/{pid}/comm"
            label = f"pid {pid}"
        else:
            comm_path = f"/proc/{pid}/task/{tid}/comm"
            label = f"tid {tid} (pid {pid})"

        try:
            with open(comm_path, "r") as comm_file:
                name = comm_file.read().strip()
                if name:
                    label = f"{label} [{name}]"
        except OSError:
            pass

        return label

    def get_grouping_description(self) -> str:
        if self.group_by == "pid":
            return "per-process (PID)"
        return "per-thread (TID)"

    def update_counts(self, elapsed=None):
        """Update all syscall counts"""
        current_rates = {}
        elapsed = self.sample_interval if elapsed is None else elapsed
        elapsed = max(elapsed, 1e-6)

        for syscall in self.syscalls:
            name = syscall["name"]

            counts = self.get_counts(name)
            total = sum(counts.values())
            self.total_counts[name] = total
            self.entity_counts[name] = counts

            rate = (
                total - self.last_counts[name]
            ) / self.sample_interval
            current_rates[name] = rate

            if rate > self.peak_rates[name]:
                self.peak_rates[name] = rate

            self.history[name].append(rate)
            self.last_counts[name] = total

        return current_rates

    def get_runtime(self):
        """Get runtime in seconds"""
        return time.time() - self.start_time

    def detach_kprobes(self):
        """Detach all kprobes"""
        for syscall in self.syscalls:
            name = syscall["name"]
            try:
                self.b.detach_kprobe(
                    event=self.b.get_syscall_fnname(name),
                    fn_name=f"trace_{name}_entry",
                )

                if "aliases" in syscall:
                    for alias in syscall["aliases"]:
                        try:
                            self.b.detach_kprobe(
                                event=self.b.get_syscall_fnname(alias),
                                fn_name=f"trace_{name}_entry",
                            )
                        except:
                            pass
            except:
                pass


class CursesDisplay:
    def __init__(self, monitor):
        self.monitor = monitor
        self.init_curses()

    def init_curses(self):
        """Initialize curses settings"""
        curses.curs_set(0)
        curses.start_color()
        curses.use_default_colors()

        # shades from empty to full: 0/8 … 8/8
        self.block_chars = [" ", "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"]

        for syscall in self.monitor.syscalls:
            color_index = syscall["color"]
            color_def = syscall.get("color_def", curses.COLOR_WHITE)
            curses.init_pair(color_index, color_def, -1)

    def format_number(self, num):
        """Format number with commas"""
        return f"{num:,}"

    def format_time(self, seconds):
        """Format time in a human-readable way"""
        if seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f} minutes"
        elif seconds < 86400:
            hours = seconds / 3600
            return f"{hours:.1f} hours"
        else:
            days = seconds / 86400
            return f"{days:.1f} days"

    def display_live_view(self, stdscr, current_rates, paused=False):
        """Display live syscall monitoring view"""
        max_y, max_x = stdscr.getmaxyx()
        hist_height = 1
        hist_width = min(self.monitor.history_size, max_x - 25)
        runtime = self.monitor.get_runtime()
        runtime_str = self.format_time(runtime)

        stdscr.clear()

        max_rates = {}
        for syscall in self.monitor.syscalls:
            name = syscall["name"]
            max_rates[name] = (
                max(self.monitor.history[name])
                if any(self.monitor.history[name])
                else 1
            )

        title = f"Syscall Rate Monitor - Running {runtime_str}"
        stdscr.addstr(0, 0, title, curses.A_BOLD)

        controls = (
            "Controls: p Pause/Resume  q Quit  +/- History  </> Interval"
        )
        stdscr.addstr(1, 0, controls, curses.A_DIM)

        status = (
            f"Interval: {self.monitor.sample_interval:.2f}s  "
            f"History: {self.monitor.history_size} samples"
        )
        if paused:
            status += "  [PAUSED]"
        stdscr.addstr(2, 0, status, curses.A_BOLD if paused else curses.A_NORMAL)

        stdscr.addstr(0, max_x - 20, "Press Ctrl+C to exit", curses.A_DIM)
        y_pos = 4

        for syscall in self.monitor.syscalls:
            name = syscall["name"]
            color = syscall["color"]
            rate = current_rates[name]
            count = self.monitor.total_counts[name]
            description = syscall["desc"]

            this_max_rate = max_rates[name]
            label = (
                f"{name:6s}: {rate:8.1f}/s (Total: "
                f"{self.format_number(count):>11s}) - {description}"
            )
            stdscr.addstr(
                y_pos,
                0,
                label,
                curses.color_pair(color) | curses.A_BOLD,
            )

            scale_label = f"[0-{this_max_rate:.1f}/s]"
            if len(label) + len(scale_label) + 2 < hist_width + 20:
                stdscr.addstr(
                    y_pos,
                    hist_width + 20,
                    scale_label,
                    curses.A_DIM,
                )
            y_pos += 1

            # single-row, 8-level Unicode block histogram
            levels = len(self.block_chars) - 1
            hist_line_y = y_pos
            history_slice = list(self.monitor.history[name])[-hist_width:]
            for i, hist_rate in enumerate(history_slice):
                ratio = hist_rate / this_max_rate if this_max_rate > 0 else 0
                lvl = int(ratio * levels + 0.5)
                lvl = max(0, min(levels, lvl))
                ch = self.block_chars[lvl]
                stdscr.addstr(
                    hist_line_y,
                    i + 20,
                    ch,
                    curses.color_pair(color),
                )
            y_pos += 2  # one for the blocks, one for spacing

            if y_pos + hist_height + 2 >= max_y:
                break

        current_time = datetime.datetime.now().strftime("%H:%M:%S")
        if max_y - 1 > 0 and max_x - len(current_time) - 1 > 0:
            stdscr.addstr(
                max_y - 1,
                max_x - len(current_time) - 1,
                current_time,
                curses.A_DIM,
            )

        stdscr.refresh()

    def display_summary(self, stdscr):
        """Display summary after monitoring stops"""
        max_y, max_x = stdscr.getmaxyx()
        runtime = self.monitor.get_runtime()

        stdscr.clear()

        start_datetime = datetime.datetime.fromtimestamp(
            self.monitor.start_time
        )
        formatted_start = start_datetime.strftime("%Y-%m-%d %H:%M:%S")
        end_datetime = datetime.datetime.now()
        formatted_end = end_datetime.strftime("%Y-%m-%d %H:%M:%S")

        stdscr.addstr(
            0,
            0,
            (
                "┌─ Syscall Monitoring Summary "
                "─────────────────────────────────┐"
            ),
            curses.A_BOLD,
        )
        stdscr.addstr(
            1,
            0,
            f"│ Start time: {formatted_start:<19s} │",
            curses.A_NORMAL,
        )
        stdscr.addstr(
            2,
            0,
            f"│ End time:   {formatted_end:<19s} │",
            curses.A_NORMAL,
        )
        stdscr.addstr(
            3,
            0,
            f"│ Duration:   {self.format_time(runtime):<19s} │",
            curses.A_NORMAL,
        )
        grouping_desc = self.monitor.get_grouping_description()
        stdscr.addstr(
            4,
            0,
            f"│ Grouping:   {grouping_desc:<19s} │",
            curses.A_NORMAL,
        )
        stdscr.addstr(
            5,
            0,
            "├──────────────────────────────────────────────────────────────┤",
            curses.A_BOLD,
        )

        category_data = {}
        for syscall in self.monitor.syscalls:
            name = syscall["name"]
            category = syscall.get("category", "uncategorized")
            count = self.monitor.total_counts[name]
            peak = self.monitor.peak_rates[name]

            category_entry = category_data.setdefault(
                category,
                {
                    "count": 0,
                    "peak_rate": 0,
                    "color": syscall.get("color"),
                    "syscalls": [],
                },
            )
            if category_entry.get("color") is None and syscall.get("color") is not None:
                category_entry["color"] = syscall.get("color")

            category_entry["count"] += count
            category_entry["peak_rate"] += peak
            category_entry["syscalls"].append(
                {
                    "name": name,
                    "count": count,
                    "peak": peak,
                    "color": syscall.get("color", 0),
                }
            )

        sorted_categories = sorted(
            category_data.items(), key=lambda item: item[1]["count"], reverse=True
        )

        y_pos = 6
        stdscr.addstr(
            y_pos,
            0,
            "│ SYSCALL  │    TOTAL CALLS    │  RATE (per sec) │  PEAK RATE  │",
            curses.A_BOLD,

        name_col_width = 16
        count_col_width = 17
        rate_num_width = 13
        peak_num_width = 9

        header_line = (
            f"│ {'CATEGORY':<{name_col_width}} │ "
            f"{'TOTAL CALLS':^{count_col_width}} │ "
            f"{'AVG RATE (/s)':^{rate_num_width + 4}} │ "
            f"{'PEAK RATE (/s)':^{peak_num_width + 4}} │"
        )
        divider_line = (
            "├"
            + "─" * (name_col_width + 2)
            + "┼"
            + "─" * (count_col_width + 2)
            + "┼"
            + "─" * (rate_num_width + 4)
            + "┼"
            + "─" * (peak_num_width + 4)
            + "┤"
        )
        bottom_line = (
            "└"
            + "─" * (name_col_width + 2)
            + "┴"
            + "─" * (count_col_width + 2)
            + "┴"
            + "─" * (rate_num_width + 4)
            + "┴"
            + "─" * (peak_num_width + 4)
            + "┘"
        )

        y_pos = 5
        stdscr.addstr(y_pos, 0, header_line, curses.A_BOLD)
        y_pos += 1
        stdscr.addstr(y_pos, 0, divider_line, curses.A_NORMAL)
        y_pos += 1

        for index, (category, stats) in enumerate(sorted_categories):
            avg_rate = stats["count"] / runtime if runtime > 0 else 0
            category_line = (
                f"│ {category:<{name_col_width}} │ "
                f"{self.format_number(stats['count']):>{count_col_width}} │ "
                f"{avg_rate:>{rate_num_width}.2f}/s │ "
                f"{stats['peak_rate']:>{peak_num_width}.2f}/s │"
            )
            stdscr.addstr(y_pos, 0, category_line, curses.A_BOLD)
            y_pos += 1

            syscall_entries = sorted(
                stats["syscalls"], key=lambda entry: entry["count"], reverse=True
            )
            for entry in syscall_entries:
                label = f"  {entry['name']}"
                avg_rate = entry["count"] / runtime if runtime > 0 else 0
                syscall_line = (
                    f"│ {label:<{name_col_width}} │ "
                    f"{self.format_number(entry['count']):>{count_col_width}} │ "
                    f"{avg_rate:>{rate_num_width}.2f}/s │ "
                    f"{entry['peak']:>{peak_num_width}.2f}/s │"
                )
                stdscr.addstr(
                    y_pos,
                    0,
                    syscall_line,
                    curses.color_pair(entry["color"]),
                )
                y_pos += 1

            if index < len(sorted_categories) - 1:
                stdscr.addstr(y_pos, 0, divider_line, curses.A_NORMAL)
                y_pos += 1

        total_count = sum(stats["count"] for stats in category_data.values())
        total_rate = total_count / runtime if runtime > 0 else 0
        max_peak = max(
            (stats["peak_rate"] for stats in category_data.values()),
            default=0,
        )

        stdscr.addstr(y_pos, 0, divider_line, curses.A_NORMAL)
        y_pos += 1
        total_line = (
            f"│ {'TOTAL':<{name_col_width}} │ "
            f"{self.format_number(total_count):>{count_col_width}} │ "
            f"{total_rate:>{rate_num_width}.2f}/s │ "
            f"{max_peak:>{peak_num_width}.2f}/s │"
        )
        stdscr.addstr(y_pos, 0, total_line, curses.A_BOLD)
        y_pos += 1
        entity_totals = collections.Counter()
        per_syscall_top = {}
        for syscall in self.monitor.syscalls:
            name = syscall["name"]
            counts = self.monitor.entity_counts.get(name, {})
            if counts:
                per_syscall_top[name] = max(counts.items(), key=lambda kv: kv[1])
            entity_totals.update(counts)

        if entity_totals:
            y_pos += 1
            stdscr.addstr(
                y_pos,
                0,
                "├────────────────────────── Top Workloads ─────────────────────┤",
                curses.A_BOLD,
            )
            y_pos += 1

            top_entities = entity_totals.most_common(5)
            for entity_id, count in top_entities:
                label = self.monitor.format_entity_label(entity_id)
                percent = (count / total_count * 100) if total_count else 0
                line = (
                    f"│ {label:<45.45s} {self.format_number(count):>12s}"
                    f" ({percent:5.1f}%) │"
                )
                stdscr.addstr(y_pos, 0, line)
                y_pos += 1

            if per_syscall_top:
                y_pos += 1
                stdscr.addstr(
                    y_pos,
                    0,
                    "├─────────────────────── Per-syscall leaders ──────────────────┤",
                    curses.A_BOLD,
                )
                y_pos += 1

                for name, (entity_id, count) in per_syscall_top.items():
                    label = self.monitor.format_entity_label(entity_id)
                    line = (
                        f"│ {name:8s} → {label:<33.33s}"
                        f" {self.format_number(count):>12s} │"
                    )
                    stdscr.addstr(y_pos, 0, line)
                    y_pos += 1

        stdscr.addstr(
            y_pos,
            0,
            (
                "└──────────┴───────────────────┴"
                "─────────────────┴─────────────┘"
            ),
            curses.A_BOLD,
        )
        stdscr.addstr(y_pos, 0, bottom_line, curses.A_BOLD)
        y_pos += 2

        if total_count > 0:
            stdscr.addstr(y_pos, 0, "Category percentage breakdown:", curses.A_BOLD)
            y_pos += 1

            bar_start = 40
            bar_width = 55

            for category, stats in sorted_categories:
                if stats["count"] <= 0:
                    continue

                percent = (stats["count"] / total_count) * 100
                bar_len = int((percent / 100) * bar_width)

                pct_line = (
                    f"{category:<{name_col_width}}: {percent:5.1f}% "
                    f"({self.format_number(stats['count'])} calls) "
                )
                stdscr.addstr(y_pos, 0, pct_line)

                color = stats.get("color") or 0
                attr = curses.color_pair(color) if color else curses.A_NORMAL
                for j in range(bar_len):
                    if bar_start + j < max_x:
                        stdscr.addch(y_pos, bar_start + j, "█", attr)

                y_pos += 1

        y_pos += 1
        if y_pos < max_y:
            stdscr.addstr(y_pos, 0, "Press any key to exit...", curses.A_DIM)

        stdscr.refresh()
        stdscr.getch()


def main_wrapper(stdscr, args):
    config = SyscallConfig(args.config)
    monitor = SyscallMonitor(
        config,
        interval=args.interval,
        history_size=args.history,
        group_by=args.group_by,
    )
    display = CursesDisplay(monitor)

    paused = False
    running = True
    current_rates = {syscall["name"]: 0 for syscall in monitor.syscalls}
    last_update = time.time() - monitor.sample_interval
    stdscr.nodelay(True)

    try:
        while running:
            now = time.time()
            if not paused and (now - last_update) >= monitor.sample_interval:
                elapsed = now - last_update
                current_rates = monitor.update_counts(elapsed=elapsed)
                last_update = now

            display.display_live_view(stdscr, current_rates, paused=paused)

            try:
                key = stdscr.getch()
            except curses.error:
                key = -1

            while key != -1:
                if key in (ord("q"), ord("Q")):
                    running = False
                    break
                if key in (ord("p"), ord("P")):
                    paused = not paused
                elif key in (ord("+"), ord("=")):
                    monitor.adjust_history_size(10)
                elif key in (ord("-"), ord("_")):
                    monitor.adjust_history_size(-10)
                elif key == ord("<"):
                    monitor.adjust_sample_interval(-0.1)
                    last_update = now
                elif key == ord(">"):
                    monitor.adjust_sample_interval(0.1)
                    last_update = now

                try:
                    key = stdscr.getch()
                except curses.error:
                    key = -1

            time.sleep(0.05)
    except KeyboardInterrupt:
        pass
    finally:
        display.display_summary(stdscr)
        monitor.detach_kprobes()
        if args.output:
            try:
                with open(args.output, "w") as f:
                    json.dump(
                        {
                            "start_time": monitor.start_time,
                            "end_time": time.time(),
                            "duration": monitor.get_runtime(),
                            "group_by": monitor.group_by,
                            "total_counts": monitor.total_counts,
                            "peak_rates": monitor.peak_rates,
                            "entity_counts": {
                                name: {
                                    str(entity): count
                                    for entity, count in entities.items()
                                }
                                for name, entities in monitor.entity_counts.items()
                            },
                        },
                        f,
                        indent=2,
                    )
                print(f"Results saved to {args.output}")
            except Exception as e:
                print(f"Error saving results: {e}")


def main():
    if os.geteuid() != 0:
        print("This script must be run as root. Please run with sudo.")
        return
    parser = argparse.ArgumentParser(
        description="Extensible Syscall Monitoring Tool"
    )
    parser.add_argument("--config", "-c", help="Configuration file (JSON)")
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
        help="History size (number of samples to display)",
    )
    parser.add_argument("--output", "-o", help="Save results to file (JSON)")
    parser.add_argument(
        "--generate-config", "-g", help="Generate default config file and exit"
    )
    parser.add_argument(
        "--group-by",
        choices=["pid", "tid"],
        default="pid",
        help="Aggregate counts per process (pid) or per thread (tid)",
    )

    args = parser.parse_args()

    if args.generate_config:
        config = SyscallConfig()
        config.save_config(args.generate_config)
        print(f"Default configuration saved to {args.generate_config}")
        return

    curses.wrapper(lambda stdscr: main_wrapper(stdscr, args))


if __name__ == "__main__":
    main()
