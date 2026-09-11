"""
Author(s):  Dávid Hanko <david.hanko@cesnet.cz>

Copyright: (C) 2023 - 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

Suricata testing module.

RSS functional test - verifies flow-to-CPU placement on a multi-queue DPDK
interface. The test is parametrized by stage so a single stage can be
selected and run in isolation via its node ID, e.g.
`functional_tests/rss/test_rss.py::test_rss[2]`:

* stage 1: single flow A is handled entirely by one worker,
* stage 2: three distinct flows B/C/D spread over multiple workers,
* stage 3: reversed flow rA (exact mirror of A's tuple) shares A's worker,
  i.e. the NIC computes a symmetric RSS hash. The reference queue is
  learned by replaying flow A first, so the stage does not depend on
  stage 1 having run in the same session.

Placement is asserted on the worker name minus the trailing interface
suffix (e.g. `W#02` of `W#02-0000:3b:00.1`), which identifies the queue
the worker reads from; the raw name is only decoration around it.
"""

import json
import logging
import os
import signal

import pytest

from lbr_testsuite import trex
from util.suricata_manager import Suricata_manager
from util.suri_util import TestInfo, get_last_stats_line
from util.test_runner import TrexTestRun
from util.trex_util import TrexMode, get_trex_mode
from conftest import kill_pytest, suri_interface_bind, Suri_conf
from assets.trex.traffic_profiles.functional_tests.rss_profile.profile import (
    RssProfile,
)

logger = logging.getLogger(__name__)

# pcap replayed per stage and the packet count expected to reach Suricata
# (small tolerance allows for steering warm-up losses)
STAGE_PCAPS = {
    1: "rss_flow_a_1000p.pcap",
    2: "rss_flows_bcd_6000p.pcap",
    3: "rss_flow_ra_500p.pcap",
}

STAGE_PACKETS = {
    1: 1000,
    2: 6000,
    3: 500,
}

PACKET_TOLERANCE = 32


def read_worker_stats(stats_path: str) -> dict[str, int]:
    """Read per-worker packet counts from the local eve-stats.json copy.

    Returns a mapping of *queue identifier* (`W#02`) to decoded packet
    count, keeping only workers that actually received traffic. The
    interface suffix is stripped because queue assignment - not the
    interface - is what RSS determines.
    """
    last = json.loads(get_last_stats_line(stats_path))

    threads = last.get("stats", {}).get("threads", {})
    placement: dict[str, int] = {}
    for name, counters in threads.items():
        if not name.startswith("W#"):
            continue
        pkts = counters.get("decoder", {}).get("pkts") or 0
        if pkts > 0:
            placement[name.split("-")[0]] = pkts
    return placement


def read_total_rx(stats_path: str) -> int:
    """Read the total decode packet count from the last stats line."""
    last = json.loads(get_last_stats_line(stats_path))
    return int(last.get("stats", {}).get("decoder", {}).get("pkts") or 0)


def assert_total_rx(stats_path: str, stage: int) -> None:
    """Assert the replayed pcap reached Suricata within tolerance."""
    total_rx = read_total_rx(stats_path)
    expected = STAGE_PACKETS[stage]
    assert expected - PACKET_TOLERANCE <= total_rx <= expected + PACKET_TOLERANCE, (
        f"stage {stage}: expected {expected - PACKET_TOLERANCE}"
        f"..{expected + PACKET_TOLERANCE} packets, got {total_rx}"
    )


@pytest.mark.parametrize(
    "stage",
    [pytest.param(s, id=str(s)) for s in (1, 2, 3)],
)
def test_rss(
    request: pytest.FixtureRequest,
    trex_generators: dict,
    result_path: str,
    suricata_tmp_stats_path: str,
    utilized_programs_info: dict,
    params: dict,
    suri_conf: Suri_conf,
    get_traffic_duration: int,
    get_heatup_duration: int,
    get_target_mac: str,
    get_target_vlan: int,
    stage: int,
):
    rules_file = "/dev/null"
    trex_manager: trex.TRexManager = trex.TRexManager(
        trex.TRexMachinesPool(trex_generators)
    )

    suri_daemon: Suricata_manager = Suricata_manager(
        request,
        suricata_tmp_stats_path,
        interface=suri_interface_bind(request)[0],
        capture_mode=suri_interface_bind(request)[1],
        conf_file=suri_conf.conf_file.with_params(params).build(),
        rules_file=rules_file,
    )
    signal.signal(signal.SIGINT, kill_pytest)

    test_info = TestInfo(
        result_path=result_path,
        traffic_duration=get_traffic_duration,
        heatup_duration=get_heatup_duration,
        suricata_path_to_bin=suri_daemon.get_path_to_binary(),
        suricata_rules_paths=[suri_daemon.rules_file],
        suricata_config_path=suri_daemon.conf_file,
        utilized_programs_info=utilized_programs_info,
    )

    trex_mode = get_trex_mode(request, [TrexMode.STL])
    trex_client = RssProfile(
        trex_manager, request, get_target_mac, get_target_vlan, mode=trex_mode
    )

    local_stats = os.path.join(
        suricata_tmp_stats_path, f"suricata-{os.environ['USER']}", "eve-stats.json"
    )

    tester = TrexTestRun(trex_client, suri_daemon, test_info, params, request)

    logger.progress(
        f"Stage {stage} ({STAGE_PCAPS[stage]}) | "
        f"param_file={request.config.getoption('--param-file')} | params={params}"
    )

    if stage == 3:
        # learn the reference queue of flow A first so this stage stays
        # correct even without stage 1 in the same session
        pcap = STAGE_PCAPS[1]
        logger.progress(f"Stage 3 pre-pass ({pcap}): learning A's queue")
        tester.execute(pcap=pcap, single_pass=True)
        assert_total_rx(local_stats, 1)
        reference_queues = set(read_worker_stats(local_stats))
        assert len(reference_queues) == 1, (
            f"stage 3 pre-pass: flow A expected on exactly one queue, "
            f"got {reference_queues}"
        )
        logger.progress(f"Stage 3 pre-pass placement: {reference_queues}")

    tester.execute(pcap=STAGE_PCAPS[stage], single_pass=True)

    placement = read_worker_stats(local_stats)
    total_rx = read_total_rx(local_stats)
    logger.progress(f"Stage {stage} placement: {placement} (total rx: {total_rx})")

    assert_total_rx(local_stats, stage)

    match stage:
        case 1:
            assert len(placement) == 1, (
                f"stage 1: flow A expected on exactly one queue, got {placement}"
            )
        case 2:
            assert len(placement) > 1, (
                f"stage 2: flows B/C/D expected on more than one queue, got {placement}"
            )
        case 3:
            ra_queues = set(placement)
            assert ra_queues == reference_queues, (
                f"stage 3: rA expected on A's queue {reference_queues}, got {ra_queues}"
            )

    logger.info(f"Stage {stage} ended.")
