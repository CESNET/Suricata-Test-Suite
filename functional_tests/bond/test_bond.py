"""
Author(s):  Dávid Hanko <david.hanko@cesnet.cz>

Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

Suricata testing module.

Bond PMD functional test - verifies traffic delivery through a DPDK bond
(logical interface combining multiple physical ports). The test is
parametrized by stage so a single stage can be selected and run in
isolation via its node ID, e.g.
`functional_tests/bond/test_bond.py::test_bond[2]`:

* stage 1: single flow A (1000 pkts) is received intact through the
  bond (pkts + bytes asserted against the generated frame length)
* stage 2: flow A delivery again - Suricata keeps receiving frames
  without a permanent stall or crash (mid-burst member link-down
  requires TRex port control, documented as a v1 limitation)
* stage 3: distinct flows B/C/D (3 x 2000 pkts) are all received -
  the aggregate delivers traffic (per-member distribution is not
  visible through the logical bond interface)

Preconditions (provisioned outside of this suite, see
functionalTesting.md "Bond PMD"):

    * a DPDK bond is configured for the capture interface - mode either
      active-backup (failover) or LACP/802.3ad (aggregation),
    * bond members negotiated where the mode requires it.
"""

import json
import logging
import os
import signal

import pytest

from lbr_testsuite import trex
from util.suri_util import TestInfo, get_last_stats_line
from util.suricata_manager import Suricata_manager
from assets.trex.traffic_profiles.functional_tests.bond_profile.profile import (
    BondProfile,
)
from conftest import kill_pytest, suri_interface_bind, Suri_conf
from util.trex_util import TrexMode, get_trex_mode
from util.test_runner import TrexTestRun

logger = logging.getLogger(__name__)

# frame length of the packets produced by generate_pcaps.py
# (14 eth [+ 4 vlan] + 20 ip + 8 udp + 1400 payload)
BASE_FRAME_LEN = 1442

# tolerance for infra noise, same as the other functional tests
TOLERANCE = 32

STAGE_PCAPS = {
    1: "bond_flow_a_1000p.pcap",
    2: "bond_flow_a_1000p.pcap",
    3: "bond_flows_bcd_6000p.pcap",
}

STAGE_PACKETS = {
    1: 1000,
    2: 1000,
    3: 6000,
}


def read_totals(stats_path: str) -> tuple[int, int]:
    """Read total decoded packets/bytes from the last stats line."""
    last = json.loads(get_last_stats_line(stats_path))
    decoder = last.get("stats", {}).get("decoder", {})
    return int(decoder.get("pkts") or 0), int(decoder.get("bytes") or 0)


@pytest.mark.parametrize(
    "stage",
    [pytest.param(s, id=str(s)) for s in (1, 2, 3)],
)
def test_bond(
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
    # bonding behavior is independent of the ruleset; always run rule-less
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
    trex_client = BondProfile(
        trex_manager, request, get_target_mac, get_target_vlan, mode=trex_mode
    )

    local_stats = os.path.join(
        suricata_tmp_stats_path, f"suricata-{os.environ['USER']}", "eve-stats.json"
    )

    tester = TrexTestRun(trex_client, suri_daemon, test_info, params, request)

    pcap = STAGE_PCAPS[stage]
    expected = STAGE_PACKETS[stage]
    # traffic is sent VLAN-tagged (see --target-vlan), so the decoded
    # frame carries an extra 4-byte 802.1Q header
    frame_len = BASE_FRAME_LEN + (4 if get_target_vlan else 0)
    logger.progress(
        f"Stage {stage} ({pcap}) | "
        f"param_file={request.config.getoption('--param-file')} | params={params}"
    )

    tester.execute(pcap=pcap, single_pass=True)

    total_rx, total_bytes = read_totals(local_stats)
    logger.progress(
        f"Stage {stage} totals: rx={total_rx} bytes={total_bytes} "
        f"(expect ~{expected} pkts x {frame_len} B)"
    )

    assert expected - TOLERANCE <= total_rx <= expected + TOLERANCE, (
        f"stage {stage}: expected {expected - TOLERANCE}..{expected + TOLERANCE} "
        f"packets, got {total_rx}"
    )

    match stage:
        case 1:
            # all frames intact through the bond (no truncation)
            assert (
                (expected - TOLERANCE) * frame_len
                <= total_bytes
                <= (expected + TOLERANCE) * frame_len
            ), f"stage 1: expected ~{expected * frame_len} bytes, got {total_bytes}"
        case 2:
            # traffic keeps flowing; Suricata did not stall or crash -
            # the run itself (start, burst, clean stop) proves liveness,
            # the totals prove delivery continued
            logger.info(
                "stage 2: delivery confirmed (no stall/crash observed). "
                "Mid-burst member link-down requires TRex port control - "
                "follow-up."
            )
        case 3:
            logger.info(
                "stage 3: aggregate delivery confirmed for flows B/C/D. "
                "Per-member distribution is not visible through the "
                "logical bond interface - follow-up."
            )

    logger.info(f"Stage {stage} ended.")
