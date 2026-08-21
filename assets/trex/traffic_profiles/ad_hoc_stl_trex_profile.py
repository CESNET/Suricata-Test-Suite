"""
Author(s):  Matyáš Sedmidubský <matyas.sedmidubsky@cesnet.cz>

Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

TRex profile template for use in Suricata-Test-Suite
"""

from .trex_client_manager import BaseAdHocTrex


class AdHocStlProfile(BaseAdHocTrex, pcaps=[]):
    """Ad-hoc STL profile that takes its pcaps at runtime."""
