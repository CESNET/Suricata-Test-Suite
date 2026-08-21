"""
Author(s):  Dávid Hanko <david.hanko@cesnet.cz>

Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

Test runner class for Suricata tests.

Provide a common interface for running Suricata tests, including setup, traffic generation, and stats collection.
"""

import pytest

from util.suricata_manager import Suricata_manager, SuriDown
from util.suri_util import RunInfo, save_stats, TestInfo


class TestRun:
    def __init__(
        self,
        suri_daemon: Suricata_manager,
        test_info: TestInfo,
        params: dict,
        request: pytest.FixtureRequest,
    ):
        self.suri_daemon = suri_daemon
        self.test_info = test_info
        self.params = params
        self.request = request

    def _before_traffic(self, multiplier: float, duration: int):
        """Prepare TRex before suricata starts (e.g. reset, set_props)."""

    def _run_traffic(self, multiplier: float, duration: int, run_info: RunInfo):
        """Generate traffic. Suricata is already running."""
        raise NotImplementedError("subclass must implement _run_traffic")

    def _collect_stats(self, run_info: RunInfo):
        """Attach TRex stats to *run_info* after traffic completes."""

    def execute(self, multiplier: float, duration: int | None = None):
        if duration is None:
            duration = self.test_info.traffic_duration

        self._before_traffic(multiplier, duration)

        try:
            self.suri_daemon.start()
        except SuriDown:
            pytest.fail("Suricata is down.")

        run_info = RunInfo(multiplier=multiplier)
        try:
            self._run_traffic(multiplier, duration, run_info)
        finally:
            try:
                self.suri_daemon.stop()
            except SuriDown:
                pytest.fail("Suricata was down.")

        self._collect_stats(run_info)
        run_info.suricata_start_delay = self.suri_daemon.last_start_delay
        save_stats(self.params, self.request, self.test_info, run_info)


class TrexTestRun(TestRun):
    """Test runner for all TRex modes (ASTF / STF / STL) via BaseTrexClientManager."""

    def __init__(
        self,
        trex_client,
        suri_daemon: Suricata_manager,
        test_info: TestInfo,
        params: dict,
        request: pytest.FixtureRequest,
    ):
        super().__init__(suri_daemon, test_info, params, request)
        self.trex_client = trex_client

    def _before_traffic(self, multiplier: float, duration: int):
        self.trex_client.set_props(multiplier, duration)
        self.trex_client.prepare()

    def _run_traffic(self, multiplier: float, duration: int, run_info: RunInfo):
        # sample TRex's own counters at the measurement-window start
        def on_measurement_start():
            run_info.trex_tx_packets_at_start = self.trex_client.get_tx_packets()
            run_info.trex_tx_bytes_at_start = self.trex_client.get_tx_bytes()

        self.trex_client.run(
            blocking=True,
            heatup=self.test_info.heatup_duration,
            on_measurement_start=on_measurement_start,
            run_info=run_info,
        )

    def _collect_stats(self, run_info: RunInfo):
        self.trex_client.update_runinfo(run_info)
