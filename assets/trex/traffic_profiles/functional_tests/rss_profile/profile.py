"""
Author(s):  Dávid Hanko <david.hanko@cesnet.cz>

Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause
"""

from pathlib import Path

from lbr_testsuite.trex import TRexManager
from pytest import FixtureRequest

from assets.trex.traffic_profiles.trex_client_manager import BaseTrexClientManager, Pcap
from util.trex_util import TrexMode


class RssProfile(
    BaseTrexClientManager,
    pcaps=[
        Pcap(Path("rss_flow_a_1000p.pcap"), 1),
        Pcap(Path("rss_flows_bcdef_10000p.pcap"), 1),
        Pcap(Path("rss_flow_ra_500p.pcap"), 1),
    ],
):
    def __init__(
        self,
        manager: TRexManager,
        request: FixtureRequest,
        target_mac: str,
        target_vlan: int = 0,
        mode=TrexMode.STL,
    ):
        super().__init__(manager, request, target_mac, target_vlan, mode=mode)
