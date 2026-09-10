"""
Author(s):  Matyáš Sedmidubský <matyas.sedmidubsky@cesnet.cz>

Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause
"""

from pathlib import Path

import lbr_trex_client.interactive.trex.astf.trex_astf_profile as astf_profile

from assets.trex.traffic_profiles.trex_client_manager import BaseTrexClientManager, Pcap

from .native import Prof1


class HttpHttpsSmbProfile(
    BaseTrexClientManager,
    pcaps=[Pcap(Path(name), weight) for name, weight in Prof1.pcaps],
):
    def get_astf_profile(self, multiplier: float) -> astf_profile.ASTFProfile:
        profile = Prof1()
        for i, pcap in enumerate(self.profile_pcaps):
            pcap_path = str(Path(__file__).parents[2] / "pcaps" / pcap.path)
            cps = pcap.weight * multiplier
            profile.pcaps[i] = (pcap_path, cps)

        return Prof1().get_profile({})
