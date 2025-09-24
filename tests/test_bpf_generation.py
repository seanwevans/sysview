import types, sys

# Stub bcc module to avoid dependency on BCC during import
bcc_stub = types.ModuleType('bcc')
bcc_stub.BPF = object
sys.modules.setdefault('bcc', bcc_stub)

import sysview


def _create_monitor(cfg):
    monitor = sysview.SyscallMonitor.__new__(sysview.SyscallMonitor)
    monitor.config = cfg
    monitor.group_by = "pid"
    return monitor


def test_generate_bpf_program_only_enabled_syscalls():
    cfg = sysview.SyscallConfig()
    # Disable all syscalls except 'read'
    for name in cfg.syscalls:
        cfg.syscalls[name]['enabled'] = (name == 'read')

    monitor = _create_monitor(cfg)
    program = sysview.SyscallMonitor.generate_bpf_program(monitor)

    # Should contain BPF map and function for 'read'
    assert 'BPF_HASH(read_count' in program
    assert 'trace_read_entry' in program
    assert 'bpf_get_current_pid_tgid' in program
    assert 'key = id >> 32;' in program

    # Disabled syscalls should not appear
    assert 'BPF_HASH(write_count' not in program
    assert 'trace_write_entry' not in program


def test_generate_bpf_program_tid_grouping():
    cfg = sysview.SyscallConfig()
    monitor = _create_monitor(cfg)
    monitor.group_by = "tid"

    program = sysview.SyscallMonitor.generate_bpf_program(monitor)

    assert 'key = id;' in program
    assert 'key = id >> 32;' not in program
