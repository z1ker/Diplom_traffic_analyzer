"""
DPIWorker — QThread that processes packets through DPIEngine asynchronously.
=============================================================================

Architecture
------------
  CaptureWorker (QThread)
       │  packet_ready signal (queued → GUI thread)
       ▼
  MainWindow._pipeline()          ← GUI thread
       │  enqueue(packet, index)   ← non-blocking
       ▼
  DPIWorker (QThread)  ─── DPIEngine (runs inside DPIWorker)
       │  result_ready signal (queued → GUI thread)
       ▼
  MainWindow._on_dpi_result()     ← GUI thread

Queue design
------------
* maxsize=1000  — bounded to avoid unbounded memory growth under high traffic.
* Packets are dropped silently when the queue is full (tracked via `dropped`).
* A sentinel object (_STOP) is pushed to shut the worker down cleanly.
"""

from __future__ import annotations

from queue import Queue, Empty

from PyQt5.QtCore import QThread, pyqtSignal

from analysis.dpi_engine import DPIEngine, DPIResult, SEVERITY_NONE


# Sentinel that causes the run-loop to exit
_STOP = object()


class DPIWorker(QThread):
    """
    Background QThread for Deep Packet Inspection.

    Signals
    -------
    result_ready(int, dict)
        Emitted for each packet that DPI produces a non-trivial result for.
        First arg is the packet index in MainWindow.packets; second is DPIResult.to_dict().
    """

    result_ready = pyqtSignal(int, dict)

    def __init__(self, max_queue: int = 1000, parent=None):
        super().__init__(parent)
        self.engine   = DPIEngine()
        self._queue:  Queue = Queue(maxsize=max_queue)
        self._dropped: int  = 0

    # ── Public API ────────────────────────────────────────────

    def enqueue(self, packet: dict, pkt_index: int) -> bool:
        """
        Submit a packet for DPI inspection.  Non-blocking.

        Returns True if the packet was queued, False if the queue was full
        and the packet was dropped.
        """
        try:
            self._queue.put_nowait((packet, pkt_index))
            return True
        except Exception:
            self._dropped += 1
            return False

    def shutdown(self, timeout_ms: int = 3000):
        """
        Signal the worker to finish processing and stop.
        Blocks until the thread exits or timeout_ms elapses.
        """
        self._queue.put(_STOP)
        self.wait(timeout_ms)

    @property
    def dropped(self) -> int:
        """Number of packets dropped due to queue overflow."""
        return self._dropped

    @property
    def queue_depth(self) -> int:
        """Approximate number of packets waiting for inspection."""
        return self._queue.qsize()

    def get_engine_stats(self) -> dict:
        return self.engine.get_stats()

    def reset_engine(self):
        self.engine.reset()
        self._dropped = 0

    # ── QThread.run ───────────────────────────────────────────

    def run(self):
        """
        Main loop — runs in the DPIWorker thread.
        Blocks on the queue, processes packets, emits results.
        """
        while True:
            # Block with a short timeout so we stay responsive to _STOP
            try:
                item = self._queue.get(timeout=0.15)
            except Empty:
                continue

            if item is _STOP:
                break

            packet, pkt_index = item

            # Pop payload so it isn't serialised back through the signal
            payload: bytes = packet.pop("payload", b"")

            try:
                result: DPIResult = self.engine.inspect(packet, payload, pkt_index)
                # Only emit when there is something meaningful to display
                if result.severity != SEVERITY_NONE:
                    self.result_ready.emit(pkt_index, result.to_dict())
            except Exception:
                # Never crash the worker thread
                pass