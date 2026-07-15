"""
Author(s):  Adam Kiripolský <adam.kiripolsky@cesnet.cz>

Copyright: (C) 2023 - 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

Parameter template example
"""

suri_yaml_params = {
    "dpdk.interfaces[0].interface": ["PCIEaddr"],
    "dpdk.interfaces[0].mtu": [2500, 3000],
}

capture_modes = ["dpdk"]
suri_cmd_params = {"capture-mode": ["dpdk"]}

filter = {"dpdk": [lambda x: x["dpdk.interfaces[0].mtu"] <= 3000]}
