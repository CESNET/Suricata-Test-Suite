"""
Author(s):  Dávid Hanko <david.hanko@cesnet.cz>

Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause
"""

from lbr_testsuite.trex import TRexManager
from pytest import FixtureRequest

from assets.trex.traffic_profiles.trex_client_manager import BaseTrexClientManager
from util.trex_util import TrexMode


class MtuProfile(
    BaseTrexClientManager,
    pcaps=[
        ("mtu_flow_a_1500_1000p.pcap", 1),
        ("mtu_flow_a_1501_1000p.pcap", 1),
        ("mtu_flow_a_7000_1000p.pcap", 1),
        ("mtu_flow_a_9000_1000p.pcap", 1),
        ("mtu_flow_a_9001_1000p.pcap", 1),
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
