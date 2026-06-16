from .trex_client_manager import BaseTrexClientManager

pcaps = [
    ("genericEBay_730P_1069B_3.pcap", 800),
    ("DNS_3P_83B.pcap", 200),
    ("http-p52728.pcap", 190),
]


class HttpProfile(BaseTrexClientManager, pcaps=pcaps):
    pass
