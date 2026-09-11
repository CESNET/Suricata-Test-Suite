"""
Author(s):  Dávid Hanko <david.hanko@cesnet.cz>

Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

Suricata testing module.

MTU functional test - verifies jumbo frame handling on a DPDK interface
with MTU 9000 (Suricata derives the mbuf/RX buffer size from the
interface MTU). The test is parametrized by stage so a single stage can
be selected and run in isolation via its node ID, e.g.
`functional_tests/mtu/test_mtu.py::test_mtu[2]`:

* stage 1 (IP len 1500): baseline, standard frames must be received whole
* stage 2 (IP len 1501): off-by-one above the standard MTU
* stage 3 (IP len 7000): mid-range jumbo, exposes undersized buffers
* stage 4 (IP len 9000): exactly the configured MTU - highest boundary
* stage 5 (IP len 9001): one byte above the MTU - frames must be rejected

Each stage starts from a fresh Suricata (implicitly covering the
BASELINE steps) and sends a single-pass 1000-packet burst of one fixed
5-tuple flow (A). Assertions compare decoder counters from the last
eve-stats line:

* decoder.pkts / decoder.ethernet - packet counts (pkts == ethernet for
  plain Ethernet frames)
* decoder.bytes - full L2 frame length including the Ethernet header,
  no CRC (GET_PKT_LEN semantics in Suricata's decode.c)
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
from assets.trex.traffic_profiles.functional_tests.mtu_profile.profile import (
    MtuProfile,
)

logger = logging.getLogger(__name__)

# test runs against the configured interface MTU (must match the
# test-local suricata.yaml dpdk.interfaces[0].mtu)
TEST_MTU = 9000

STAGE_PCAPS = {
    1: "mtu_flow_a_1500_1000p.pcap",
    2: "mtu_flow_a_1501_1000p.pcap",
    3: "mtu_flow_a_7000_1000p.pcap",
    4: "mtu_flow_a_9000_1000p.pcap",
    5: "mtu_flow_a_9001_1000p.pcap",
}

STAGE_IP_LEN = {
    1: 1500,
    2: 1501,
    3: 7000,
    4: 9000,
    5: 9001,
}

PACKETS_PER_STAGE = 1000
ETHERNET_HEADER_LEN = 14
VLAN_TAG_LEN = 4
PKT_TOLERANCE = 32


def read_decoder_stats(stats_path: str) -> dict[str, int]:
    """Read the decoder counters relevant for MTU from the last stats line."""
    last = json.loads(get_last_stats_line(stats_path))
    decoder = last.get("stats", {}).get("decoder", {})
    capture = last.get("stats", {}).get("capture", {}).get("dpdk", {})
    return {
        "pkts": int(decoder.get("pkts") or 0),
        "ethernet": int(decoder.get("ethernet") or 0),
        "bytes": int(decoder.get("bytes") or 0),
        "imissed": int(capture.get("imissed") or 0),
    }


@pytest.mark.parametrize(
    "stage",
    [pytest.param(s, id=str(s)) for s in (1, 2, 3, 4, 5)],
)
def test_mtu(
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

    # The MTU the test asserts against must match the test-local yaml.
    # with_params() would let the parametrized value override it, so the
    # forced MTU has to be set last, right before build().
    param_mtu = params.get("dpdk.interfaces[0].mtu")
    if param_mtu is not None and int(param_mtu) != TEST_MTU:
        logger.warning(
            "Overriding parametrized dpdk.interfaces[0].mtu=%s with %d "
            "required by the MTU test",
            param_mtu,
            TEST_MTU,
        )
    suri_daemon: Suricata_manager = Suricata_manager(
        request,
        suricata_tmp_stats_path,
        interface=suri_interface_bind(request)[0],
        capture_mode=suri_interface_bind(request)[1],
        conf_file=suri_conf.conf_file.with_params(params)
        .set_option("dpdk.interfaces[0].mtu", TEST_MTU)
        .build(),
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
    trex_client = MtuProfile(
        trex_manager, request, get_target_mac, get_target_vlan, mode=trex_mode
    )

    local_stats = os.path.join(
        suricata_tmp_stats_path, f"suricata-{os.environ['USER']}", "eve-stats.json"
    )

    tester = TrexTestRun(trex_client, suri_daemon, test_info, params, request)

    pcap = STAGE_PCAPS[stage]
    ip_len = STAGE_IP_LEN[stage]
    # traffic is sent VLAN-tagged (see --target-vlan), so the decoded frame
    # carries an extra 4-byte 802.1Q header after the Ethernet header
    frame_len = ip_len + ETHERNET_HEADER_LEN + (VLAN_TAG_LEN if get_target_vlan else 0)
    logger.progress(
        f"Stage {stage} ({pcap}) | ip_len={ip_len} frame_len={frame_len} | "
        f"param_file={request.config.getoption('--param-file')} | params={params}"
    )

    tester.execute(pcap=pcap, single_pass=True)

    stats = read_decoder_stats(local_stats)
    logger.progress(
        f"Stage {stage} decoder: pkts={stats['pkts']} "
        f"ethernet={stats['ethernet']} bytes={stats['bytes']} "
        f"imissed={stats['imissed']} "
        f"(expected pkts={PACKETS_PER_STAGE} bytes={PACKETS_PER_STAGE * frame_len})"
    )

    match stage:
        case 1 | 2 | 3 | 4:
            # MEASURING 1-4: frame counts and byte sums must match the
            # burst; per-packet average must equal the full frame length
            # exactly (no partial frames counted as valid)
            assert (
                PACKETS_PER_STAGE - PKT_TOLERANCE
                <= stats["pkts"]
                <= PACKETS_PER_STAGE + PKT_TOLERANCE
            ), (
                f"stage {stage}: expected "
                f"{PACKETS_PER_STAGE - PKT_TOLERANCE}..{PACKETS_PER_STAGE + PKT_TOLERANCE} "
                f"packets, got {stats['pkts']}"
            )
            assert (
                PACKETS_PER_STAGE - PKT_TOLERANCE
                <= stats["ethernet"]
                <= PACKETS_PER_STAGE + PKT_TOLERANCE
            ), (
                f"stage {stage}: expected "
                f"{PACKETS_PER_STAGE - PKT_TOLERANCE}..{PACKETS_PER_STAGE + PKT_TOLERANCE} "
                f"ethernet frames, got {stats['ethernet']}"
            )
            actual_avg = stats["bytes"] / stats["pkts"] if stats["pkts"] else 0
            assert abs(actual_avg - frame_len) <= 1.0, (
                f"stage {stage}: average packet size {actual_avg} != expected "
                f"frame length {frame_len} - frames are being truncated"
            )
        case 5:
            # MEASURING 5: frames above the MTU must be rejected - received
            # neither as valid packets nor silently truncated
            assert stats["pkts"] <= PKT_TOLERANCE, (
                f"stage {stage}: ip_len {ip_len} exceeds MTU {TEST_MTU} but "
                f"{stats['pkts']} packets were received"
            )

    logger.info(f"Stage {stage} ended.")
