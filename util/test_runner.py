"""
Author(s):  Dávid Hanko <davihan11@gmail.com>

Copyright: (C) 2026 CESNET, z.s.p.o.

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

    def _run_traffic(self, multiplier: float, duration: int):
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

        self._run_traffic(multiplier, duration)

        try:
            self.suri_daemon.stop()
        except SuriDown:
            pytest.fail("Suricata was down.")

        run_info = RunInfo(multiplier=multiplier)
        self._collect_stats(run_info)
        run_info.suricata_start_delay = self.suri_daemon.last_start_delay
        save_stats(self.params, self.request, self.test_info, run_info)


class AstfTestRun(TestRun):
    """Test runner for ASTF / STF TRex modes via BaseTrexClientManager."""

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

    def _run_traffic(self, multiplier: float, duration: int):
        self.trex_client.run()

    def _collect_stats(self, run_info: RunInfo):
        self.trex_client.update_runinfo(run_info)


class PcapReplayTestRun(TestRun):
    """Test runner for stateless pcap replay via raw TRexStateless."""

    def __init__(
        self,
        traffic_generator,
        pcap_filename: str,
        suri_daemon: Suricata_manager,
        test_info: TestInfo,
        params: dict,
        request: pytest.FixtureRequest,
    ):
        super().__init__(suri_daemon, test_info, params, request)
        self.traffic_generator = traffic_generator
        self.pcap_filename = pcap_filename

    def _before_traffic(self, multiplier: float, duration: int):
        self.traffic_generator.reset()

    def _run_traffic(self, multiplier: float, duration: int):
        from conftest import return_filename

        self.traffic_generator.get_handler().push_remote(
            pcap_filename=f"/tmp/pcaps/{return_filename(self.pcap_filename)}",
            ports=[0],
            ipg_usec=100,
            speedup=200 * multiplier,
            duration=duration,
        )
        self.traffic_generator.wait_on_traffic()

    def _collect_stats(self, run_info: RunInfo):
        run_info.trex_server_stats = self.traffic_generator.get_stats()
        run_info.trex_pretty_stats["opackets"] = run_info.trex_server_stats["total"][
            "opackets"
        ]
        run_info.trex_pretty_stats["obytes"] = run_info.trex_server_stats["total"][
            "obytes"
        ]
