#!/usr/bin/env python3
""" csview.py — realtime eBPF flame graph """

import argparse, hashlib, signal, sys, time
import curses
from bcc import BPF, PerfType, PerfSWConfig

PALETTE = []


def colour(name):
    if not PALETTE:
        return 0

    if isinstance(name, bytes):
        name = name.decode("utf-8", "replace")

    return PALETTE[int(hashlib.md5(name.encode()).hexdigest(), 16) % len(PALETTE)]


def sym(addr, pid, b):
    return b.sym(addr, pid=pid, show_offset=False) if addr else "[miss]"


def harvest(b, windowed=False):
    """Return {stack-tuple: samples}; clear map if windowed mode."""
    stacks, counts = b["stacks"], b["counts"]
    out = {tuple(stacks.walk(k.value)): v.value for k, v in counts.items()}
    if windowed:
        counts.clear()
    return out


def tui(scr):
    argp = argparse.ArgumentParser(description="Realtime terminal flame graph")
    argp.add_argument("--pid", required=True, type=int, help="target PID")
    argp.add_argument("--freq", default=97, type=int, help="sampling Hz")
    argp.add_argument(
        "--win", default=1.0, type=float, help="UI refresh seconds; 0 = fastest"
    )
    argp.add_argument(
        "--margin", default=2, type=int, help="columns to keep blank on right"
    )
    argp.add_argument(
        "-w",
        "--windowed",
        action="store_true",
        help="rolling window (clear counters every refresh)",
    )
    args = argp.parse_args()

    bpf_src = f"""
    #include <uapi/linux/ptrace.h>
    BPF_HASH(counts, u64, u64, 16384);
    BPF_STACK_TRACE(stacks, 16384);
    int do_sample(struct pt_regs *ctx) {{
        if ((bpf_get_current_pid_tgid() >> 32) != {args.pid}) return 0;
        int id = stacks.get_stackid(ctx, BPF_F_USER_STACK);
        if (id < 0) return 0;
        u64 key=id, zero=0, *v = counts.lookup_or_init(&key, &zero); (*v)++;
        return 0;
    }}
    """
    b = BPF(text=bpf_src)
    b.attach_perf_event(
        ev_type=PerfType.SOFTWARE,
        ev_config=PerfSWConfig.CPU_CLOCK,
        fn_name="do_sample",
        sample_freq=args.freq,
        pid=-1,
        cpu=-1,
    )

    curses.curs_set(0)
    curses.start_color()
    curses.use_default_colors()
    for i, fg in enumerate(
        (
            curses.COLOR_CYAN,
            curses.COLOR_GREEN,
            curses.COLOR_MAGENTA,
            curses.COLOR_YELLOW,
            curses.COLOR_BLUE,
            curses.COLOR_RED,
        ),
        1,
    ):
        curses.init_pair(i, fg, -1)
        PALETTE.append(i)

    h, w = scr.getmaxyx()
    last = 0

    while True:
        now = time.time()
        if args.win == 0 or now - last >= args.win:
            last = now
            data = harvest(b, args.windowed)
            total = sum(data.values()) or 1

            scr.erase()
            graph_w = max(1, w - args.margin)
            remaining, x_cursor = graph_w, 0

            for idx, (stk, samp) in enumerate(
                sorted(data.items(), key=lambda kv: kv[1], reverse=True)
            ):
                width = (
                    remaining
                    if idx == len(data) - 1
                    else max(1, min(remaining, int(samp / total * graph_w)))
                )
                remaining -= width

                for depth, addr in enumerate(stk):
                    y = h - depth - 1
                    if y < 1:
                        break
                    attr = curses.color_pair(colour(sym(addr, args.pid, b)))
                    for col in range(x_cursor, x_cursor + width):
                        scr.addch(y, col, curses.ACS_CKBOARD, attr)

                x_cursor += width
                if remaining <= 0:
                    break

            mode = "windowed" if args.windowed else "cumulative"
            scr.addstr(
                0,
                0,
                f"PID {args.pid} | {args.freq} Hz | {mode} win={args.win:.1f}s "
                f"| samples {total} | q:quit",
            )
            scr.refresh()

        # keys / resize
        scr.nodelay(True)
        k = scr.getch()
        if k in (ord("q"), ord("Q")):
            break
        elif k in (ord("r"), ord("R"), curses.KEY_RESIZE):
            h, w = scr.getmaxyx()
        time.sleep(0.02)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    curses.wrapper(tui)
