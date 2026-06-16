from assets.trex.traffic_profiles.trex_client_manager import BaseTrexClientManager

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


class HttpHttpsSmbProfile(BaseTrexClientManager, pcaps=pcaps):
    pass
