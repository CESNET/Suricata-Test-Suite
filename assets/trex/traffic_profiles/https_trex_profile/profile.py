from pathlib import Path

import lbr_trex_client.interactive.trex.astf.trex_astf_profile as astf_profile
from assets.trex.traffic_profiles.trex_client_manager import BaseTrexClientManager

from .native import Prof1

native = Prof1()
defaults = native.pcaps


class HttpsProfile(BaseTrexClientManager, pcaps=native.pcaps):
    def get_astf_profile(self, multiplier: float) -> astf_profile.ASTFProfile:
        for i in range(len(native.pcaps)):
            cap = Path(__file__).parent.parent / "pcaps" / defaults[i][0]
            cps = defaults[i][1] * multiplier
            native.pcaps[i] = (str(cap), cps)

        profile = native.get_profile({})

        return profile
