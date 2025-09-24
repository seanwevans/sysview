import types, sys

import pytest

# Provide a stub for the bcc module so sysview imports without system dependencies
bcc_stub = types.ModuleType('bcc')
bcc_stub.BPF = object
sys.modules.setdefault('bcc', bcc_stub)

import sysview


def test_merge_config_overrides_and_adds():
    cfg = sysview.SyscallConfig()
    user_cfg = {
        'syscalls': {
            'write': {'enabled': False, 'color': 99},
            'newcall': {
                'name': 'newcall',
                'color': 10,
                'color_def': 1,
                'desc': 'test syscall',
                'enabled': True,
            },
        }
    }
    cfg.merge_config(user_cfg)

    # existing key overridden
    assert cfg.syscalls['write']['enabled'] is False
    assert cfg.syscalls['write']['color'] == 99

    # new syscall added
    assert 'newcall' in cfg.syscalls
    assert cfg.syscalls['newcall']['name'] == 'newcall'

    enabled = cfg.get_enabled_syscalls()
    assert 'write' not in enabled  # disabled in user config
    assert 'newcall' in enabled


def test_merge_config_requires_fields():
    cfg = sysview.SyscallConfig()

    with pytest.raises(ValueError):
        cfg.merge_config({'syscalls': {'broken': {'color': 1}}})


def test_merge_config_validates_aliases_type():
    cfg = sysview.SyscallConfig()

    with pytest.raises(ValueError):
        cfg.merge_config({'syscalls': {'read': {'aliases': 'not-a-list'}}})


def test_enabled_syscalls_include_category():
    cfg = sysview.SyscallConfig()
    enabled = cfg.get_enabled_syscalls()

    assert enabled['read']['category'] == 'file'
