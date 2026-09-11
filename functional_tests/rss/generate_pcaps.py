"""
Author(s):  Dávid Hanko <david.hanko@cesnet.cz>

Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

Generate the pcaps used by the RSS functional test (test_rss.py).

Three pcaps are produced (see STAGE_PCAPS in the test):

* `rss_flow_a_1000p.pcap`    - single flow A, 1000 packets
* `rss_flows_bcd_6000p.pcap` - three distinct flows B/C/D, 6000 packets
  (round-robin interleaved, 2000 packets per flow)
* `rss_flow_ra_500p.pcap`    - reversed flow rA, the exact tuple mirror
  of flow A, 500 packets (stage 3 symmetric-hash check)

5-tuples are fixed per flow so the NIC RSS hash stays constant within a
flow; the payload bytes differ per packet so loss/reordering is
detectable. rA must keep the exact mirrored tuple of A - only the
direction (and payload tag) differ.

MACs are placeholders; TRex rewrites the destination MAC at send time
(`set_dst_mac`). Pcap timestamps are deterministic (STL replay pacing
comes from `push_remote`'s ipg_usec, not from the pcap).

Update the packet budgets and re-run when the test stages change.
"""

import struct
from pathlib import Path

from scapy.all import Ether, IP, TCP, wrpcap

# packet budget per pcap (must match STAGE_PACKETS in test_rss.py)
COUNT_A = 1000
COUNT_RA = 500
COUNT_BCD_PER_FLOW = 2000  # x3 flows = 6000

# fixed 5-tuple of flow A and its exact mirror rA
FLOW_A = ("16.0.0.1", 1024, "48.0.0.1", 80)
FLOW_RA = (FLOW_A[2], FLOW_A[3], FLOW_A[0], FLOW_A[1])

# three distinct flows for the queue-spread stage (RFC 5737 addresses)
FLOWS_BCD = [
    ("203.0.113.1", 41000, "198.51.100.7", 2101),
    ("192.0.2.2", 52000, "198.51.100.9", 2102),
    ("198.18.0.11", 63000, "203.0.113.11", 2103),
]

# placeholder MACs; TRex rewrites the destination MAC at send time
SRC_MAC = "02:00:00:00:00:01"
DST_MAC = "02:00:00:00:00:02"

# initial sequence numbers of the client/server sides
ISN_CLIENT = 1
ISN_SERVER = 1

# deterministic inter-packet gaps (seconds)
IPG_FLOW = 0.0001  # A / rA: 100 us -> 10 kpps
IPG_BCD = 0.001  # per-flow grid in the B/C/D interleave
BCD_FLOW_OFFSET = 0.5  # flow k starts k * offset later

# payload shaping
BCD_DATA_LEN = 1400  # 4-byte big-endian index + X padding

OUTPUT_DIR = (
    Path(__file__).resolve().parents[2]
    / "assets"
    / "trex"
    / "traffic_profiles"
    / "pcaps"
)


def _frame(
    src_ip: str, sport: int, dst_ip: str, dport: int, flags, seq, ack, payload=b""
):
    """Build one TCP packet of a flow."""
    return (
        Ether(src=SRC_MAC, dst=DST_MAC, type=0x0800)
        / IP(src=src_ip, dst=dst_ip)
        / TCP(sport=sport, dport=dport, flags=flags, seq=seq, ack=ack, window=8192)
        / payload
    )


def _tagged_index(tag: str, idx: int) -> bytes:
    """Flow-tagged payload coding the packet index (e.g. b'A0000042')."""
    return f"{tag}{idx:07d}".encode()


def build_flow_packets(src_ip, sport, dst_ip, dport, count, tag):
    """Build one pcap worth of a single bidirectional flow.

    Structure: SYN / SYN-ACK / ACK handshake, one-direction data
    packets with index-tagged payloads, FIN / ACK / FIN / ACK
    teardown - `count` packets in total.
    """
    data_count = count - 7
    packets = []
    t = 0.0

    def emit(pkt):
        nonlocal t
        pkt.time = t
        packets.append(pkt)
        t += IPG_FLOW

    emit(_frame(src_ip, sport, dst_ip, dport, "S", ISN_CLIENT, 0))
    emit(_frame(dst_ip, dport, src_ip, sport, "SA", ISN_SERVER, ISN_CLIENT + 1))
    emit(_frame(src_ip, sport, dst_ip, dport, "A", ISN_CLIENT + 1, ISN_SERVER + 1))

    seq = ISN_CLIENT + 1
    for i in range(data_count):
        payload = _tagged_index(tag, i)
        emit(_frame(src_ip, sport, dst_ip, dport, "PA", seq, ISN_SERVER + 1, payload))
        seq += len(payload)

    emit(_frame(src_ip, sport, dst_ip, dport, "FA", seq, ISN_SERVER + 1))
    emit(_frame(dst_ip, dport, src_ip, sport, "A", ISN_SERVER + 1, seq + 1))
    emit(_frame(dst_ip, dport, src_ip, sport, "FA", ISN_SERVER + 1, seq + 1))
    emit(_frame(src_ip, sport, dst_ip, dport, "A", seq + 1, ISN_SERVER + 2))

    return packets


def build_bcd_packets():
    """Build the interleaved multi-flow pcap.

    Each of the three flows carries a handshake plus one-direction
    data (4-byte big-endian index + X padding). Flows start
    BCD_FLOW_OFFSET apart and are merged by timestamp, so the
    replayed traffic overlaps in time.
    """
    flow_packets = []
    for flow_idx, (src_ip, sport, dst_ip, dport) in enumerate(FLOWS_BCD):
        packets = []
        t = flow_idx * BCD_FLOW_OFFSET

        def emit(pkt):
            nonlocal t
            pkt.time = t
            packets.append(pkt)
            t += IPG_BCD

        emit(_frame(src_ip, sport, dst_ip, dport, "S", ISN_CLIENT, 0))
        emit(_frame(dst_ip, dport, src_ip, sport, "SA", ISN_SERVER, ISN_CLIENT + 1))
        emit(_frame(src_ip, sport, dst_ip, dport, "A", ISN_CLIENT + 1, ISN_SERVER + 1))

        data_count = COUNT_BCD_PER_FLOW - 3
        seq = ISN_CLIENT + 1
        for i in range(data_count):
            payload = struct.pack(">I", i) + b"X" * (BCD_DATA_LEN - 4)
            emit(
                _frame(src_ip, sport, dst_ip, dport, "PA", seq, ISN_SERVER + 1, payload)
            )
            seq += len(payload)

        flow_packets.extend(packets)

    return sorted(flow_packets, key=lambda pkt: float(pkt.time))


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    outputs = [
        (build_flow_packets(*FLOW_A, COUNT_A, "A"), "rss_flow_a_1000p.pcap"),
        (build_flow_packets(*FLOW_RA, COUNT_RA, "rA"), "rss_flow_ra_500p.pcap"),
        (build_bcd_packets(), "rss_flows_bcd_6000p.pcap"),
    ]

    for packets, name in outputs:
        out = OUTPUT_DIR / name
        wrpcap(str(out), packets)
        print(f"{out.name}: {len(packets)} packets")


if __name__ == "__main__":
    main()
