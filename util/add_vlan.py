"""
Copyright: (C) 2023 - 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause
"""

import logging
import socket
from pathlib import Path

import dpkt

from util.cache_util import cache_path, try_cache

logger = logging.getLogger(__name__)


def fix_checksums(eth):
    ip = None
    if isinstance(eth.data, dpkt.ethernet.VLANtag8021Q):
        vlan = eth.data
        if isinstance(vlan.data, dpkt.ip.IP):
            ip = vlan.data
    elif isinstance(eth.data, dpkt.ip.IP):
        ip = eth.data

    if not ip:
        return

    ip.len = len(ip)
    ip.sum = 0
    ip.sum = dpkt.in_cksum(ip.pack_hdr())

    if isinstance(ip.data, dpkt.tcp.TCP):
        tcp = ip.data
        tcp.sum = 0
        pseudo_hdr = dpkt.struct.pack(
            "!4s4sBBH", ip.src, ip.dst, 0, socket.IPPROTO_TCP, len(tcp)
        )
        tcp.sum = dpkt.in_cksum(pseudo_hdr + bytes(tcp))
    elif isinstance(ip.data, dpkt.udp.UDP):
        udp = ip.data
        udp.sum = 0
        pseudo_hdr = dpkt.struct.pack(
            "!4s4sBBH", ip.src, ip.dst, 0, socket.IPPROTO_UDP, len(udp)
        )
        udp.sum = dpkt.in_cksum(pseudo_hdr + bytes(udp))


def edit_vlan(pcap_filename, vlan_id):
    if vlan_id == 0:
        return pcap_filename

    source_name = Path(pcap_filename).name
    target_name = f"vlan{vlan_id}.pcap"

    cached = try_cache(target_name, [source_name])
    if cached is not None:
        return str(cached)

    created_pcap_filename = cache_path(target_name, source_name)
    logger.debug(
        "Creating VLAN-tagged pcap: %s -> %s (vlan_id=%d)",
        pcap_filename,
        created_pcap_filename,
        vlan_id,
    )

    with open(pcap_filename, "rb") as f_in, open(created_pcap_filename, "wb") as f_out:
        reader = dpkt.pcap.Reader(f_in)
        writer = dpkt.pcap.Writer(f_out)

        for ts, buf in reader:
            try:
                eth = dpkt.ethernet.Ethernet(buf)

                if isinstance(eth.data, dpkt.ethernet.VLANtag8021Q):
                    eth.data.id = vlan_id
                else:
                    vlan = dpkt.ethernet.VLANtag8021Q()
                    vlan.pri = 0
                    vlan.cfi = 0
                    vlan.id = vlan_id
                    vlan.type = eth.type
                    vlan.data = eth.data
                    eth.type = dpkt.ethernet.ETH_TYPE_8021Q
                    eth.data = vlan

                fix_checksums(eth)
                writer.writepkt(eth.pack(), ts)

            except Exception:
                writer.writepkt(buf, ts)  # Fallback for malformed packets

        return str(created_pcap_filename)
