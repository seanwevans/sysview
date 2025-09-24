import json
import socket
import threading
import types


# Stub bcc module to avoid dependency on BCC during import
bcc_stub = types.ModuleType("bcc")
bcc_stub.BPF = object


def _ensure_bcc_stub():
    import sys

    sys.modules.setdefault("bcc", bcc_stub)


_ensure_bcc_stub()

import sysview


class _MockMonitor:
    def __init__(self):
        self._runtime = 1.5
        self.total_counts = {"read": 10, "write": 5}
        self.peak_rates = {"read": 7.2, "write": 4.4}

    def get_runtime(self):
        return self._runtime


def test_metrics_streamer_json_file(tmp_path):
    output = tmp_path / "metrics.jsonl"
    streamer = sysview.MetricsStreamer(file_path=str(output), fmt="json")
    monitor = _MockMonitor()
    streamer.write_snapshot(monitor, {"read": 3.0, "write": 1.0})
    streamer.close()

    entries = output.read_text().strip().splitlines()
    assert len(entries) == 1
    data = json.loads(entries[0])
    assert data["rates"]["read"] == 3.0
    assert data["totals"]["write"] == 5
    assert data["peak_rates"]["read"] == 7.2


def test_metrics_streamer_prometheus_socket(tmp_path):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]

    received = []

    def _accept():
        conn, _ = server.accept()
        with conn:
            received.append(conn.recv(4096).decode("utf-8"))
        server.close()

    thread = threading.Thread(target=_accept)
    thread.daemon = True
    thread.start()

    streamer = sysview.MetricsStreamer(
        socket_address=("127.0.0.1", port), fmt="prometheus"
    )
    monitor = _MockMonitor()
    streamer.write_snapshot(monitor, {"read": 2.5, "write": 0.5})
    streamer.close()

    thread.join(timeout=5)
    assert received, "No data received from streamer"
    payload = received[0]
    assert "sysview_syscall_rate{syscall=\"read\"} 2.5" in payload
    assert "sysview_syscall_total{syscall=\"write\"} 5" in payload
