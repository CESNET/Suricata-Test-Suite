"""
Author(s):  Matyáš Sedmidubský <matyas.sedmidubsky@cesnet.cz>

Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

TRex profile template for use in Suricata-Test-Suite
"""

from pathlib import Path

from util.config_builder import ConfigBuilder

from .trex_client_manager import BaseTrexClientManager

# taken from web_50_sites/profile.yaml
pcaps = [
    ("web_50_sites/dns.pcap", 51),
    ("web_50_sites/google-cloud.pcap", 1),
    ("web_50_sites/googlecloud_210315.pcap", 1),
    ("web_50_sites/pornhub.pcap", 1),
    ("web_50_sites/amazon_services.pcap", 1),
    ("web_50_sites/apple_news.pcap", 1),
    ("web_50_sites/google-maps.pcap", 1),
    ("web_50_sites/google_play_gquic.pcap", 1),
    ("web_50_sites/googleplay_210622.pcap", 1),
    ("web_50_sites/itunes.pcap", 1),
    ("web_50_sites/xvideos.pcap", 1),
    ("web_50_sites/xvideos_210601.pcap", 1),
    ("web_50_sites/akamai_cloud_bbc.pcap", 1),
    ("web_50_sites/instagram_video.pcap", 1),
    ("web_50_sites/instagram_210607.pcap", 1),
    ("web_50_sites/pornhub-network.pcap", 1),
    ("web_50_sites/youtube_quic.pcap", 1),
    ("web_50_sites/youtube_210623.pcap", 1),
    ("web_50_sites/facebook_cloud.pcap", 1),
    ("web_50_sites/facebookcloud_video.pcap", 1),
    ("web_50_sites/hulu.pcap", 1),
    ("web_50_sites/facebook.pcap", 1),
    ("web_50_sites/facebook_210625.pcap", 1),
    ("web_50_sites/snapchat.pcap", 1),
    ("web_50_sites/snapchat_210609.pcap", 1),
    ("web_50_sites/snapchat_video.pcap", 1),
    ("web_50_sites/google_services.pcap", 1),
    ("web_50_sites/netflix_video.pcap", 1),
    ("web_50_sites/netflix_210611.pcap", 1),
    ("web_50_sites/instagram.pcap", 1),
    ("web_50_sites/instagram_210607.pcap", 1),
    ("web_50_sites/apple-services.pcap", 1),
    ("web_50_sites/facetime.pcap", 1),
    ("web_50_sites/facetime_210219.pcap", 1),
    ("web_50_sites/fastly.pcap", 1),
    ("web_50_sites/google_ads.pcap", 1),
    ("web_50_sites/googleads_210622.pcap", 1),
    ("web_50_sites/google_apis.pcap", 1),
    ("web_50_sites/googleapis_210620.pcap", 1),
    ("web_50_sites/pandora.pcap", 1),
    ("web_50_sites/pandora-audio.pcap", 1),
    ("web_50_sites/pinterest.pcap", 1),
    ("web_50_sites/playstation.pcap", 1),
    ("web_50_sites/playstation_210620.pcap", 1),
    ("web_50_sites/twitch.pcap", 1),
    ("web_50_sites/twitch_210615.pcap", 1),
    ("web_50_sites/whatsapp.pcap", 1),
    ("web_50_sites/whatsapp_210624.pcap", 1),
    ("web_50_sites/xbox.pcap", 1),
    ("web_50_sites/yahoo.pcap", 1),
    ("web_50_sites/youtube-music.pcap", 1),
    ("web_50_sites/youtubemusic_210625.pcap", 1),
]


class Web50SitesProfile(BaseTrexClientManager, pcaps=pcaps):
    def stf_config_hook(self, config: ConfigBuilder) -> ConfigBuilder:
        config.add_option("[0].memory.traffic_mbuf_2048", 128_000)
        return config

    def get_remote_data_path(self, local_path: Path) -> Path:
        return Path(f"/opt/trex/{self.trex_version}/web_50_sites") / local_path.name
