#!/usr/bin/env python3
""" hview.py — realtime eBPF heap-flame graph (bytes live per call-stack) """

import argparse
import hashlib
import signal
import sys
import time
import curses
from pathlib import Path
from bcc import BPF

PALETTE: list[int] = []  # colour-hash palette


# ────────── helpers ──────────────────────────────────────────────────────────
def colour(name: str | bytes) -> int:
    """Return a stable palette index for a symbol name."""
    if not PALETTE:
        return 0
    if isinstance(name, bytes):
        name = name.decode("utf-8", "replace")
    return PALETTE[int(hashlib.md5(name.encode()).hexdigest(), 16) % len(PALETTE)]


def sym(addr: int, pid: int, b: BPF) -> str:
    """Resolve an address to a user-space symbol, or ‘[miss]’."""
    return b.sym(addr, pid=pid, show_offset=False) if addr else "[miss]"


def find_libc(pid: int) -> Path:
    """Best-effort: return the libc path used by the target PID."""
    for line in Path(f"/proc/{pid}/maps").read_text().splitlines():
        if "r-xp" in line and ("libc.so" in line or "libc-" in line):
            return Path(line.split()[-1])
    raise RuntimeError("could not locate libc for target process")


def harvest(b: BPF, windowed: bool = False) -> dict[tuple[int, ...], int]:
    """Return {stack-tuple: bytes_live}; clear map if windowed mode."""
    stacks, counts = b["stacks"], b["counts"]
    out = {tuple(stacks.walk(k.value)): v.value for k, v in counts.items()}
    if windowed:
        counts.clear()
    return out


# ────────── curses UI loop ───────────────────────────────────────────────────
def tui(scr):
    # ─── CLI ──────────────────────────────────────────────────────────────
    argp = argparse.ArgumentParser(description="Realtime heap flame-graph")
    argp.add_argument("--pid", required=True, type=int, help="target PID")
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

    # ─── eBPF program ─────────────────────────────────────────────────
    libc = find_libc(args.pid)

    bpf_src = r"""
    #include <uapi/linux/ptrace.h>
    BPF_HASH(ptr_sz, u64, u64);              // ptr → size
    BPF_HASH(tmp_sz, u32, u64);              // tid → size (malloc entry)
    BPF_STACK_TRACE(stacks, 16384);
    BPF_HASH(counts, u64, u64, 16384);       // stack-id → live bytes

    // -------- allocation entry probes ----------------------------------
    int alloc_enter(struct pt_regs *ctx, size_t size) {
        u32 tid = bpf_get_current_pid_tgid();
        tmp_sz.update(&tid, &size);
        return 0;
    }
    // -------- malloc / realloc return ----------------------------------
    int alloc_ret(struct pt_regs *ctx) {
        u32 tid = bpf_get_current_pid_tgid();
        u64 *szp = tmp_sz.lookup(&tid);
        if (!szp) return 0;
        size_t size = *szp;
        tmp_sz.delete(&tid);

        void *ptr = (void *)PT_REGS_RC(ctx);
        if (!ptr) return 0;

        u64 addr = (u64)ptr;
        ptr_sz.update(&addr, &size);

        int id = stacks.get_stackid(ctx, BPF_F_USER_STACK);
        if (id < 0) return 0;

        u64 key = id, zero = 0, *v = counts.lookup_or_init(&key, &zero);
        *v += size;
        return 0;
    }
    // -------- free ------------------------------------------------------
    int free_enter(struct pt_regs *ctx, void *ptr) {
        if (!ptr) return 0;
        u64 addr = (u64)ptr;
        u64 *szp = ptr_sz.lookup(&addr);
        if (!szp) return 0;
        u64 size = *szp;
        ptr_sz.delete(&addr);

        int id = stacks.get_stackid(ctx, BPF_F_USER_STACK);
        if (id < 0) return 0;

        u64 key = id, zero = 0, *v = counts.lookup_or_init(&key, &zero);
        if (*v > size) *v -= size; else *v = 0;
        return 0;
    }
    """

    b = BPF(text=bpf_src)

    # attach alloc/free probes on the *target’s* libc
    for sym_name in ("malloc", "calloc", "realloc"):
        b.attach_uprobe(
            name=str(libc), sym=sym_name, pid=args.pid, fn_name="alloc_enter"
        )
        b.attach_uretprobe(
            name=str(libc), sym=sym_name, pid=args.pid, fn_name="alloc_ret"
        )
    b.attach_uprobe(name=str(libc), sym="free", pid=args.pid, fn_name="free_enter")

    # ─── curses palette init ─────────────────────────────────────────
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

    # ─── main loop ───────────────────────────────────────────────────
    while True:
        now = time.time()
        if args.win == 0 or now - last >= args.win:
            last = now
            data = harvest(b, args.windowed)
            total = sum(data.values()) or 1  # total live bytes

            scr.erase()
            graph_w = max(1, w - args.margin)
            remaining, x_cursor = graph_w, 0

            for idx, (stk, bytes_live) in enumerate(
                sorted(data.items(), key=lambda kv: kv[1], reverse=True)
            ):
                width = (
                    remaining
                    if idx == len(data) - 1
                    else max(1, min(remaining, int(bytes_live / total * graph_w)))
                )
                remaining -= width

                for depth, addr in enumerate(stk):
                    y = h - depth - 1
                    if y < 1:
                        break
                    clr = colour(sym(addr, args.pid, b))
                    attr = curses.color_pair(clr)
                    for col in range(x_cursor, x_cursor + width):
                        scr.addch(y, col, curses.ACS_CKBOARD, attr)

                x_cursor += width
                if remaining <= 0:
                    break

            mode = "windowed" if args.windowed else "cumulative"
            total_str = (
                f"{total/1024:.1f} KiB"
                if total < 1 << 20
                else f"{total/1024/1024:.2f} MiB"
            )
            scr.addstr(
                0,
                0,
                f"PID {args.pid} | heap {total_str} | {mode} win={args.win:.1f}s "
                f"| q:quit",
            )
            scr.refresh()

        # keys / resize
        scr.nodelay(True)
        k = scr.getch()
        if k in (ord("q"), ord("Q")):
            break
        elif k in (ord("r"), ord("R"), curses.KEY_RESIZE):
            h, w = scr.getmaxyx()
        time.sleep(0.03)


# ────────── main ────────────────────────────────────────────────────────────
if __name__ == "__main__":
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    curses.wrapper(tui)
