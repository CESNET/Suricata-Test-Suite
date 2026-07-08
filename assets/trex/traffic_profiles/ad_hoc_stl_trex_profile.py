"""
Author(s): Matyáš Sedmidubský <matyas.sedmidubsky@cesnet.cz>

Copyright: (C) 2026 CESNET, z.s.p.o.

TRex profile template for use in Suricata-Test-Suite
"""

from lbr_testsuite.trex import TRexManager
from pytest import FixtureRequest

from .trex_client_manager import BaseTrexClientManager, PcapList, TrexMode


class AdHocStlProfile(BaseTrexClientManager, pcaps=[]):
    def __init__(
        self,
        pcaps: PcapList,
        manager: TRexManager,
        request: FixtureRequest,
        target_mac: str,
        target_vlan: int = 0,
    ):
        self.profile_pcaps = pcaps
        super().__init__(manager, request, target_mac, target_vlan, mode=TrexMode.STL)
