"""
Author(s):  Eliška Červinková <eliska.cervinkova@cesnet.cz>
            Matyáš Sedmidubský <matyas.sedmidubsky@cesnet.cz>

Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause
"""

from trex.astf.api import *


class Prof1:
    def __init__(self):
        pass

    pcaps = [
        ("dark_reader.pcap", 120.0),
        ("genericEBay_730P_1069B_3.pcap", 80.0),
        ("cisco.pcap", 80.0),
        ("kerberos.pcap", 120.0),
        ("jpg_download.pcap", 120.0),
        ("google_maps.pcap", 120.0),
        ("youtube.pcap", 80.0),
        ("netflix.pcap", 50.0),
        ("reddit.pcap", 60.0),
        ("my_liftor.pcap", 70.0),
        ("smbtorture_1.pcap", 50.0),
        ("smbtorture_4.pcap", 100.0),
    ]

    def get_profile(self, tunables, **kwargs):
        client_global_info = ASTFGlobalInfo()
        client_global_info.ip.dont_use_inbound_mac = 1
        # https://github.com/CESNET/lbr-testsuite/blob/ab02f9fed69144e060e0bb3ad611a434b34b13cb/lbr_testsuite/trex/trex_stateful.py#L462
        client_global_info.ip.tos = 0x2

        server_global_info = ASTFGlobalInfo()
        server_global_info.ip.dont_use_inbound_mac = 1
        server_global_info.ip.tos = 0x2

        client_ip_dist = ASTFIPGenDist(
            ip_range=["16.0.0.0", "16.0.0.255"], distribution="seq"
        )
        server_ip_dist = ASTFIPGenDist(
            ip_range=["48.0.0.0", "48.0.255.255"], distribution="seq"
        )
        ip_gen = ASTFIPGen(dist_client=client_ip_dist, dist_server=server_ip_dist)

        return ASTFProfile(
            default_ip_gen=ip_gen,
            cap_list=[ASTFCapInfo(file=cap, cps=cps) for cap, cps in self.pcaps],
            default_c_glob_info=client_global_info,
            default_s_glob_info=server_global_info,
        )


def register():
    return Prof1()
