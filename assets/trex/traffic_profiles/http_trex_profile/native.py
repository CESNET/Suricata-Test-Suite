from trex.astf.api import *


class Prof1:
    def __init__(self):
        pass

    pcaps = [
        ("genericEBay_730P_1069B_3.pcap", 800.0),
        ("DNS_3P_83B.pcap", 200.0),
        ("http-p52728.pcap", 190.0),
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
