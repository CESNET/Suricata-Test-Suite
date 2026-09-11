"""
Author(s):  Dávid Hanko <david.hanko@cesnet.cz>

Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

Generator of testing pcaps for the Bond PMD functional test
(functionalTesting.md "Bond PMD").

Produced pcaps (written to assets/trex/traffic_profiles/pcaps/):

* bond_flow_a_1000p.pcap - 1000 packets of a single flow (A),
  UDP with 1400B payload, used for frame-delivery and failover stages.
* bond_flows_bcd_6000p.pcap - 3 distinct flows (B, C, D) x 2000 packets
  each, UDP with 1400B payload, used for the LACP aggregation stage.
"""

from pathlib import Path

from scapy.all import Ether, IP, UDP, wrpcap

# --- flow definitions -------------------------------------------------------
# 5-tuples of the testing flows; A/B/C/D according to functionalTesting.md

FLOWS = {
    "a": {"ip_src": "192.168.50.1", "ip_dst": "192.168.60.1", "port": 5001},
    "b": {"ip_src": "192.168.50.2", "ip_dst": "192.168.60.2", "port": 5002},
    "c": {"ip_src": "192.168.50.3", "ip_dst": "192.168.60.3", "port": 5003},
    "d": {"ip_src": "192.168.50.4", "ip_dst": "192.168.60.4", "port": 5004},
}

SRC_MAC = "aa:bb:cc:dd:ee:01"
DST_MAC = "aa:bb:cc:dd:ee:02"

PAYLOAD_SIZE = 1400  # bytes of UDP payload

OUTPUT_DIR = (
    Path(__file__).resolve().parents[2]
    / "assets"
    / "trex"
    / "traffic_profiles"
    / "pcaps"
)


def build_packets(flow: dict, count: int) -> list:
    """Build `count` UDP packets of one flow with a fixed payload size."""
    return [
        Ether(src=SRC_MAC, dst=DST_MAC)
        / IP(src=flow["ip_src"], dst=flow["ip_dst"])
        / UDP(sport=flow["port"], dport=flow["port"])
        / (b"B" * PAYLOAD_SIZE)
        for _ in range(count)
    ]


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # stage 1 + 2: single flow A
    wrpcap(str(OUTPUT_DIR / "bond_flow_a_1000p.pcap"), build_packets(FLOWS["a"], 1000))

    # stage 3: distinct flows B, C, D (2000 each, interleaved)
    flows_bcd = [FLOWS["b"], FLOWS["c"], FLOWS["d"]]
    packets = []
    for i in range(2000):
        for flow in flows_bcd:
            packets.extend(build_packets(flow, 1))
    wrpcap(str(OUTPUT_DIR / "bond_flows_bcd_6000p.pcap"), packets)

    print(f"pcaps written to {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
