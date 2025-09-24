#!/usr/bin/env python3

import argparse
import collections
import datetime
import json
import os
import time

from bcc import BPF
import curses


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
            },
            "read": {
                "name": "read",
                "color": 2,
                "color_def": curses.COLOR_CYAN,
                "desc": "Reading from files/pipes",
                "enabled": True,
            },
            "open": {
                "name": "open",
                "color": 3,
                "color_def": curses.COLOR_YELLOW,
                "desc": "Opening files",
                "enabled": True,
            },
            "close": {
                "name": "close",
                "color": 4,
                "color_def": curses.COLOR_RED,
                "desc": "Closing file descriptors",
                "enabled": True,
            },
            "mmap": {
                "name": "mmap",
                "color": 5,
                "color_def": curses.COLOR_MAGENTA,
                "desc": "Memory mapping",
                "enabled": True,
            },
            "socket": {
                "name": "socket",
                "color": 6,
                "color_def": curses.COLOR_BLUE,
                "desc": "Network socket operations",
                "enabled": True,
            },
            "poll": {
                "name": "poll",
                "color": 7,
                "color_def": curses.COLOR_WHITE,
                "desc": "I/O event notifications (poll/select/epoll)",
                "enabled": True,
                "aliases": ["select", "epoll_wait"],
            },
            "futex": {
                "name": "futex",
                "color": 8,
                "color_def": 208,  # Orange
                "desc": "Fast user-space locking",
                "enabled": True,
            },
            "execve": {
                "name": "execve",
                "color": 9,
                "color_def": 85,  # Teal
                "desc": "Execute programs",
                "enabled": True,
            },
        }

        self.syscalls = self.default_syscalls.copy()

        if filename and os.path.exists(filename):
            try:
                with open(filename, "r") as f:
                    user_config = json.load(f)
                    self.merge_config(user_config)
            except Exception as e:
                print(f"Error loading config file: {e}")

    def merge_config(self, user_config):
        """Merge user configuration with defaults"""
        if "syscalls" in user_config:
            for syscall_name, syscall_config in user_config[
                "syscalls"
            ].items():
                if syscall_name in self.syscalls:
                    for key, value in syscall_config.items():
                        self.syscalls[syscall_name][key] = value
                else:
                    self.syscalls[syscall_name] = syscall_config

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


class SyscallMonitor:
    def __init__(self, config, interval=1, history_size=60, group_by="pid"):
        self.config = config
        self.sample_interval = interval
        self.history_size = history_size
        self.start_time = time.time()
        self.group_by = group_by

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

    def attach_kprobes(self):
        """Attach kprobes for all enabled syscalls"""
        enabled_syscalls = self.config.get_enabled_syscalls()

        for name, config in enabled_syscalls.items():
            try:
                self.b.attach_kprobe(
                    event=self.b.get_syscall_fnname(name),
                    fn_name=f"trace_{name}_entry",
                )

                if "aliases" in config:
                    for alias in config["aliases"]:
                        try:
                            self.b.attach_kprobe(
                                event=self.b.get_syscall_fnname(alias),
                                fn_name=f"trace_{name}_entry",
                            )
                        except Exception as e:
                            print(
                                f"Warning: Failed to attach alias {alias} for {name}: {e}"
                            )

            except Exception as e:
                print(f"Warning: Failed to attach probe for {name}: {e}")

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

    def update_counts(self):
        """Update all syscall counts"""
        current_rates = {}

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

    def display_live_view(self, stdscr, current_rates):
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
        stdscr.addstr(0, max_x - 20, "Press Ctrl+C to exit", curses.A_DIM)
        y_pos = 2

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

        sorted_syscalls = sorted(
            [
                (
                    syscall["name"],
                    self.monitor.total_counts[syscall["name"]],
                    self.monitor.peak_rates[syscall["name"]],
                )
                for syscall in self.monitor.syscalls
            ],
            key=lambda x: x[1],
            reverse=True,
        )

        y_pos = 6
        stdscr.addstr(
            y_pos,
            0,
            "│ SYSCALL  │    TOTAL CALLS    │  RATE (per sec) │  PEAK RATE  │",
            curses.A_BOLD,
        )
        y_pos += 1
        stdscr.addstr(
            y_pos,
            0,
            (
                "├──────────┼───────────────────┼"
                "─────────────────┼─────────────┤"
            ),
            curses.A_NORMAL,
        )
        y_pos += 1

        for name, count, peak in sorted_syscalls:
            for syscall in self.monitor.syscalls:
                if syscall["name"] == name:
                    color = syscall["color"]
                    break

            avg_rate = count / runtime if runtime > 0 else 0

            syscall_line = (
                f"│ {name:8s} │ {self.format_number(count):>17s} │ "
                f"{avg_rate:13.2f}/s │ {peak:9.2f}/s │"
            )
            stdscr.addstr(y_pos, 0, syscall_line, curses.color_pair(color))
            y_pos += 1

        total_count = sum(self.monitor.total_counts.values())
        total_rate = total_count / runtime if runtime > 0 else 0
        max_peak = max(self.monitor.peak_rates.values())

        stdscr.addstr(
            y_pos,
            0,
            "├──────────┼───────────────────┼─────────────────┼─────────────┤",
            curses.A_NORMAL,
        )
        y_pos += 1
        total_line = (
            f"│ TOTAL    │ {self.format_number(total_count):>17s} │ "
            f"{total_rate:13.2f}/s │ {max_peak:9.2f}/s │"
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
        y_pos += 2

        if total_count > 0:
            stdscr.addstr(y_pos, 0, "Percentage breakdown:", curses.A_BOLD)
            y_pos += 1

            bar_start = 40
            bar_width = 55

            for i, (name, count, _) in enumerate(sorted_syscalls):
                if count > 0:
                    for syscall in self.monitor.syscalls:
                        if syscall["name"] == name:
                            color = syscall["color"]
                            break

                    percent = (count / total_count) * 100
                    bar_len = int((percent / 100) * bar_width)

                    pct_line = (
                        f"{name:8s}: {percent:5.1f}% "
                        f"({self.format_number(count)} calls) "
                    )
                    stdscr.addstr(y_pos, 0, pct_line)

                    for j in range(bar_len):
                        if bar_start + j < max_x:
                            stdscr.addch(
                                y_pos,
                                bar_start + j,
                                "█",
                                curses.color_pair(color),
                            )

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

    try:
        while True:
            current_rates = monitor.update_counts()
            display.display_live_view(stdscr, current_rates)
            time.sleep(monitor.sample_interval)
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
