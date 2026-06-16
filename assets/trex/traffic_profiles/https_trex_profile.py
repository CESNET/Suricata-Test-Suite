from .trex_client_manager import BaseTrexClientManager

pcaps = [
    ("https.pcap", 1500),
    ("https_web.pcap", 1800),
    ("https_info.pcap", 700),
    ("https_bbc.pcap", 1800),
    ("https_info_user.pcap", 1400),
]


class HttpsProfile(BaseTrexClientManager, pcaps=pcaps):
    pass
