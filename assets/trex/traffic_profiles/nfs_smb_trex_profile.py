from .trex_client_manager import BaseTrexClientManager

pcaps = [
    ("nfsv2.pcap", 40),
    ("nfsv3.pcap", 40),
    ("nfsv4.pcap", 40),
    ("nfs_simple.pcap", 25),
    ("nfs_50MB_file.pcap", 17),
    ("smbtorture_1.pcap", 25),
    ("smbtorture_2.pcap", 20),
    ("smbtorture_3.pcap", 25),
    ("smbtorture_4.pcap", 25),
    ("smbtorture_5.pcap", 25),
    ("smbtorture_6.pcap", 20),
]


class NfsSmbProfile(BaseTrexClientManager, pcaps=pcaps):
    pass
