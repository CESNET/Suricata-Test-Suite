"""
Author(s):  Dávid Hanko <david.hanko@cesnet.cz>

Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

Generate the pcaps used by the MTU functional test.

Each pcap carries a burst of 1000 packets from a single fixed 5-tuple
flow (A) at a given *IP total length* (MTU is an L3 constraint):

* 1500 - baseline, standard frame
* 1501 - off-by-one above the standard MTU
* 7000 - mid-range jumbo, probes undersized buffers
* 9000 - configured interface MTU boundary
* 9001 - one byte above the MTU, must be rejected by the NIC

Update STAGES and re-run when the test stages change.
"""

from pathlib import Path

from scapy.all import Ether, IP, UDP, wrpcap

# (IP total length, packet count) per stage
STAGES = {
    1500: 1000,
    1501: 1000,
    7000: 1000,
    9000: 1000,
    9001: 1000,
}

# fixed 5-tuple of flow A
SRC_IP = "10.0.0.1"
DST_IP = "10.0.0.2"
SRC_PORT = 1024
DST_PORT = 8080

# placeholder MACs matching the RSS pcaps; TRex rewrites the destination
# MAC at send time (`set_dst_mac`) so these never reach the wire as-is
SRC_MAC = "02:00:00:00:00:01"
DST_MAC = "02:00:00:00:00:02"

# L2/L3/L4 overhead: eth(14) + ip(20) + udp(8) = 42
ETHERNET_HEADER_LEN = 14
IPV4_HEADER_LEN = 20
UDP_HEADER_LEN = 8

OUTPUT_DIR = (
    Path(__file__).resolve().parents[2]
    / "assets"
    / "trex"
    / "traffic_profiles"
    / "pcaps"
)


def build_flow_packet(ip_total_len: int, seq: int):
    """Build one packet of flow A with the requested IP total length.

    `seq` drives the payload content so packet loss/reordering is
    detectable, while keeping the 5-tuple fixed. The IP length is set
    explicitly so it is exactly the MTU-relevant L3 size.
    """
    payload_len = ip_total_len - IPV4_HEADER_LEN - UDP_HEADER_LEN
    prefix = f"mtu-test-{seq}-".encode()
    payload = (prefix * (payload_len // len(prefix) + 1))[:payload_len]

    pkt = (
        Ether(src=SRC_MAC, dst=DST_MAC, type=0x0800)
        / IP(
            src=SRC_IP,
            dst=DST_IP,
            len=ip_total_len,
            flags="DF",
        )
        / UDP(sport=SRC_PORT, dport=DST_PORT)
        / payload
    )
    # strip any payload excess so len matches exactly, then compute checksums
    del pkt[IP].chksum
    del pkt[UDP].chksum
    return pkt


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    for ip_total_len, count in STAGES.items():
        packets = [build_flow_packet(ip_total_len, i) for i in range(count)]
        out = OUTPUT_DIR / f"mtu_flow_a_{ip_total_len}_1000p.pcap"
        wrpcap(str(out), packets)
        frame_len = ip_total_len + ETHERNET_HEADER_LEN
        print(
            f"{out.name}: {count} packets, ip_len={ip_total_len}, frame_len={frame_len}"
        )


if __name__ == "__main__":
    main()
