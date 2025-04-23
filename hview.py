#!/usr/bin/env python3
# hview.py — realtime heap flamegraph (bytes-live per call-stack)

import argparse, curses, signal, time, sys, os, hashlib, subprocess, pathlib
from bcc import BPF, PerfType, PerfSWConfig  # only for constants

# ───── CLI ──────────────────────────────────────────────────────────
ap = argparse.ArgumentParser(description="Realtime heap flame graph via eBPF")
ap.add_argument("--pid", required=True, type=int, help="target PID")
ap.add_argument(
    "--win", default=1.0, type=float, help="UI refresh seconds; 0 = fastest"
)
ap.add_argument("--margin", default=2, type=int, help="blank cols at right edge")
ap.add_argument(
    "--windowed", "-w", action="store_true", help="rolling window instead of cumulative"
)
args = ap.parse_args()

target_pid = args.pid


# ───── locate libc for the target (so uprobe hits the right binary) ──────────
def find_libc(pid):
    maps = open(f"/proc/{pid}/maps").read().splitlines()
    for line in maps:
        if "r-xp" in line and ("libc.so" in line or "libc-" in line):
            return line.split()[-1]
    raise RuntimeError("could not locate libc for target PID")


libc_path = find_libc(target_pid)

# ───── eBPF program ────────────────────────────────────────────────
bpf_src = r"""
#include <uapi/linux/ptrace.h>
BPF_HASH(ptr_sz, u64, u64);            // key: address, value: bytes
BPF_STACK_TRACE(stacks, 16384);
BPF_HASH(counts, u64, u64, 16384);     // key: stack-id, value: live bytes

// malloc / calloc / realloc entry: stash size in TLS slot (per-PID)
BPF_HASH(tmp_size, u32, u64);

int trace_alloc_enter(struct pt_regs *ctx, size_t size)
{
    u32 tid = bpf_get_current_pid_tgid();
    tmp_size.update(&tid, &size);
    return 0;
}

// malloc return: get ptr, size, stack -> counts & ptr_sz
int trace_alloc_return(struct pt_regs *ctx)
{
    u32 tid = bpf_get_current_pid_tgid();
    u64 *sizep = tmp_size.lookup(&tid);
    if (!sizep) return 0;
    size_t sz = *sizep;
    tmp_size.delete(&tid);

    void *ptr = (void *)PT_REGS_RC(ctx);
    if (!ptr) return 0;

    // remember ptr -> size so free can reverse it
    u64 addr = (u64)ptr;
    ptr_sz.update(&addr, &sz);

    int id = stacks.get_stackid(ctx, BPF_F_USER_STACK);
    if (id < 0) return 0;

    u64 key = id, *bytes = counts.lookup_or_init(&key, & (u64){0});
    *bytes += sz;
    return 0;
}

// free(ptr): look up size, subtract
int trace_free(struct pt_regs *ctx, void *ptr)
{
    if (!ptr) return 0;
    u64 addr = (u64)ptr;
    u64 *szp = ptr_sz.lookup(&addr);
    if (!szp) return 0;                // freeing something we didn't track
    u64 sz = *szp;
    ptr_sz.delete(&addr);

    int id = stacks.get_stackid(ctx, BPF_F_USER_STACK);
    if (id < 0) return 0;

    u64 key = id, *bytes = counts.lookup_or_init(&key, & (u64){0});
    if (*bytes > sz) *bytes -= sz; else *bytes = 0;
    return 0;
}
"""
b = BPF(text=bpf_src)

# attach to target libc’s malloc(), calloc(), realloc(), free()
for sym in ("malloc", "calloc", "realloc"):
    b.attach_uprobe(
        name=libc_path, sym=sym, pid=target_pid, fn_name="trace_alloc_enter"
    )
    b.attach_uretprobe(
        name=libc_path, sym=sym, pid=target_pid, fn_name="trace_alloc_return"
    )
b.attach_uprobe(name=libc_path, sym="free", pid=target_pid, fn_name="trace_free")

stacks = b.get_table("stacks")
counts = b.get_table("counts")

# ───── helpers (same palette + UI bits you already have) ───────────
PALETTE = []


def colour(name):
    if not PALETTE:
        return 0
    if isinstance(name, bytes):
        name = name.decode("utf-8", "replace")
    return PALETTE[int(hashlib.md5(name.encode()).hexdigest(), 16) % len(PALETTE)]


def sym(addr):
    return b.sym(addr, pid=target_pid, show_offset=False) if addr else "[miss]"


def grab():
    out = {tuple(stacks.walk(k.value)): v.value for k, v in counts.items()}
    if args.windowed:
        counts.clear()
    return out


# ───── curses flame-TUI (identical to csview.py logic) ─────────────
def tui(scr):
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
            data = grab()
            total = sum(data.values()) or 1
            scr.erase()

            graph_w = max(1, w - args.margin)
            remaining = graph_w
            x_cursor = 0
            items = sorted(data.items(), key=lambda kv: kv[1], reverse=True)
            for idx, (stk, bytes_live) in enumerate(items):
                width = (
                    remaining
                    if idx == len(items) - 1
                    else max(1, min(remaining, int(bytes_live / total * graph_w)))
                )
                remaining -= width
                for depth, addr in enumerate(stk):
                    y = h - depth - 1
                    if y < 1:
                        break
                    attr = curses.color_pair(colour(sym(addr)))
                    for col in range(x_cursor, x_cursor + width):
                        scr.addch(y, col, curses.ACS_CKBOARD, attr)
                x_cursor += width
                if remaining <= 0:
                    break

            mode = "windowed" if args.windowed else "cumulative"
            pretty_total = (
                f"{total/1024:.1f} KiB"
                if total < 10**6
                else f"{total/1024/1024:.2f} MiB"
            )
            scr.addstr(
                0,
                0,
                f"PID {target_pid} | heap {pretty_total} | {mode} "
                f"win={args.win:.1f}s | q:quit",
            )
            scr.refresh()

        scr.nodelay(True)
        k = scr.getch()
        if k in (ord("q"), ord("Q")):
            break
        elif k in (ord("r"), ord("R"), curses.KEY_RESIZE):
            h, w = scr.getmaxyx()
        time.sleep(0.03)


signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
curses.wrapper(tui)
