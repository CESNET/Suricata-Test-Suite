from pathlib import Path

from util.config_builder import ConfigBuilder

from .trex_client_manager import BaseTrexClientManager, TrexMode

# taken from upf_dns_top50.yaml
pcaps = [
    ("upf_top50/dns.pcap", 51),
    ("upf_top50/google-cloud.pcap", 1),
    ("upf_top50/googlecloud_210315.pcap", 1),
    ("upf_top50/pornhub.pcap", 1),
    ("upf_top50/amazon_services.pcap", 1),
    ("upf_top50/apple_news.pcap", 1),
    ("upf_top50/google-maps.pcap", 1),
    ("upf_top50/google_play_gquic.pcap", 1),
    ("upf_top50/googleplay_210622.pcap", 1),
    ("upf_top50/itunes.pcap", 1),
    ("upf_top50/xvideos.pcap", 1),
    ("upf_top50/xvideos_210601.pcap", 1),
    ("upf_top50/akamai_cloud_bbc.pcap", 1),
    ("upf_top50/instagram_video.pcap", 1),
    ("upf_top50/instagram_210607.pcap", 1),
    ("upf_top50/pornhub-network.pcap", 1),
    ("upf_top50/youtube_quic.pcap", 1),
    ("upf_top50/youtube_210623.pcap", 1),
    ("upf_top50/facebook_cloud.pcap", 1),
    ("upf_top50/facebookcloud_video.pcap", 1),
    ("upf_top50/hulu.pcap", 1),
    ("upf_top50/facebook.pcap", 1),
    ("upf_top50/facebook_210625.pcap", 1),
    ("upf_top50/snapchat.pcap", 1),
    ("upf_top50/snapchat_210609.pcap", 1),
    ("upf_top50/snapchat_video.pcap", 1),
    ("upf_top50/google_services.pcap", 1),
    ("upf_top50/netflix_video.pcap", 1),
    ("upf_top50/netflix_210611.pcap", 1),
    ("upf_top50/instagram.pcap", 1),
    ("upf_top50/instagram_210607.pcap", 1),
    ("upf_top50/apple-services.pcap", 1),
    ("upf_top50/facetime.pcap", 1),
    ("upf_top50/facetime_210219.pcap", 1),
    ("upf_top50/fastly.pcap", 1),
    ("upf_top50/google_ads.pcap", 1),
    ("upf_top50/googleads_210622.pcap", 1),
    ("upf_top50/google_apis.pcap", 1),
    ("upf_top50/googleapis_210620.pcap", 1),
    ("upf_top50/pandora.pcap", 1),
    ("upf_top50/pandora-audio.pcap", 1),
    ("upf_top50/pinterest.pcap", 1),
    ("upf_top50/playstation.pcap", 1),
    ("upf_top50/playstation_210620.pcap", 1),
    ("upf_top50/twitch.pcap", 1),
    ("upf_top50/twitch_210615.pcap", 1),
    ("upf_top50/whatsapp.pcap", 1),
    ("upf_top50/whatsapp_210624.pcap", 1),
    ("upf_top50/xbox.pcap", 1),
    ("upf_top50/yahoo.pcap", 1),
    ("upf_top50/youtube-music.pcap", 1),
    ("upf_top50/youtubemusic_210625.pcap", 1),
]


class UpfDns50Profile(BaseTrexClientManager, pcaps=pcaps):
    def is_mode_allowed(self, mode: TrexMode) -> bool:
        return mode == TrexMode.STF

    def get_stf_profile(self) -> Path:
        return self.PCAP_PATH_PREFIX / "upf_top50" / "upf_dns_top50.yaml"

    def stf_config_hook(self, config: ConfigBuilder) -> ConfigBuilder:
        config.add_option("[0].memory.traffic_mbuf_2048", 128_000)
        return config

    def get_remote_data_path(self, local_path: Path) -> Path:
        if local_path == self.get_stf_profile():
            # place in default location
            return super().get_remote_data_path(local_path)
        else:
            assert self.trex_version is not None
            return Path(f"/opt/trex/{self.trex_version}/upf_top50") / local_path.name
