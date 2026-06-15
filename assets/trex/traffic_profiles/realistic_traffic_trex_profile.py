from pathlib import Path

from util.config_builder import ConfigBuilder

from .trex_client_manager import BaseTrexClientManager, TrexMode

# taken from realistic_traffic.yaml
pcaps = [
    ("stf_realistic/dns.pcap", 51),
    ("stf_realistic/google-cloud.pcap", 1),
    ("stf_realistic/googlecloud_210315.pcap", 1),
    ("stf_realistic/pornhub.pcap", 1),
    ("stf_realistic/amazon_services.pcap", 1),
    ("stf_realistic/apple_news.pcap", 1),
    ("stf_realistic/google-maps.pcap", 1),
    ("stf_realistic/google_play_gquic.pcap", 1),
    ("stf_realistic/googleplay_210622.pcap", 1),
    ("stf_realistic/itunes.pcap", 1),
    ("stf_realistic/xvideos.pcap", 1),
    ("stf_realistic/xvideos_210601.pcap", 1),
    ("stf_realistic/akamai_cloud_bbc.pcap", 1),
    ("stf_realistic/instagram_video.pcap", 1),
    ("stf_realistic/instagram_210607.pcap", 1),
    ("stf_realistic/pornhub-network.pcap", 1),
    ("stf_realistic/youtube_quic.pcap", 1),
    ("stf_realistic/youtube_210623.pcap", 1),
    ("stf_realistic/facebook_cloud.pcap", 1),
    ("stf_realistic/facebookcloud_video.pcap", 1),
    ("stf_realistic/hulu.pcap", 1),
    ("stf_realistic/facebook.pcap", 1),
    ("stf_realistic/facebook_210625.pcap", 1),
    ("stf_realistic/snapchat.pcap", 1),
    ("stf_realistic/snapchat_210609.pcap", 1),
    ("stf_realistic/snapchat_video.pcap", 1),
    ("stf_realistic/google_services.pcap", 1),
    ("stf_realistic/netflix_video.pcap", 1),
    ("stf_realistic/netflix_210611.pcap", 1),
    ("stf_realistic/instagram.pcap", 1),
    ("stf_realistic/instagram_210607.pcap", 1),
    ("stf_realistic/apple-services.pcap", 1),
    ("stf_realistic/facetime.pcap", 1),
    ("stf_realistic/facetime_210219.pcap", 1),
    ("stf_realistic/fastly.pcap", 1),
    ("stf_realistic/google_ads.pcap", 1),
    ("stf_realistic/googleads_210622.pcap", 1),
    ("stf_realistic/google_apis.pcap", 1),
    ("stf_realistic/googleapis_210620.pcap", 1),
    ("stf_realistic/pandora.pcap", 1),
    ("stf_realistic/pandora-audio.pcap", 1),
    ("stf_realistic/pinterest.pcap", 1),
    ("stf_realistic/playstation.pcap", 1),
    ("stf_realistic/playstation_210620.pcap", 1),
    ("stf_realistic/twitch.pcap", 1),
    ("stf_realistic/twitch_210615.pcap", 1),
    ("stf_realistic/whatsapp.pcap", 1),
    ("stf_realistic/whatsapp_210624.pcap", 1),
    ("stf_realistic/xbox.pcap", 1),
    ("stf_realistic/yahoo.pcap", 1),
    ("stf_realistic/youtube-music.pcap", 1),
    ("stf_realistic/youtubemusic_210625.pcap", 1),
]


class RealisticTrafficProfile(BaseTrexClientManager, pcaps=pcaps):
    def is_mode_allowed(self, mode: TrexMode) -> bool:
        return mode == TrexMode.STF

    def get_stf_profile(self) -> Path:
        return self.PCAP_PATH_PREFIX / "stf_realistic" / "realistic_traffic.yaml"

    def stf_config_hook(self, config: ConfigBuilder) -> ConfigBuilder:
        config.add_option("[0].memory.traffic_mbuf_2048", 128_000)
        return config

    def get_remote_data_path(self, local_path: Path) -> Path:
        if local_path == self.get_stf_profile():
            # place in default location
            return super().get_remote_data_path(local_path)
        else:
            assert self.trex_version is not None
            return Path(f"/opt/trex/{self.trex_version}/stf_realistic") / local_path.name
