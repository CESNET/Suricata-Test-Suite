"""
Author(s):  Matyáš Sedmidubský <matyas.sedmidubsky@cesnet.cz>

Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

TRex profile template for use in Suricata-Test-Suite
"""

import logging
import os
import re
import warnings
from pathlib import Path
from time import sleep, time
from typing import Callable, Dict, Literal, NamedTuple, Self

from lbr_testsuite.trex import (
    TRexAdvancedStateful,
    TRexManager,
    TRexStateless,
)

# NOTE: import the TRex client classes via the `trex` alias (set up in
# conftest.py as `sys.modules["trex"] = lbr_trex_client.interactive.trex`).
# lbr_testsuite.trex imports them the same way, so using the alias path here
# guarantees the classes are identical to the ones the TRex clients check
# against in `isinstance()` (e.g. STLClient.add_streams). Importing from
# `lbr_trex_client.interactive.trex.*` instead would create distinct class
# objects and break those checks.
from trex.astf import trex_astf_profile
from trex.astf.trex_astf_client import ASTFClient
from trex.common.trex_exceptions import TRexError
from trex.stl.trex_stl_client import STLClient
from trex.stl.trex_stl_packet_builder_scapy import STLPktBuilder
from trex.stl.trex_stl_streams import STLStream, STLTXSingleBurst
from trex_client import CTRexClient
from pytest import FixtureRequest

from util.add_vlan import edit_vlan
from util.config_builder import ConfigBuilder
from util.suri_util import RunInfo
from util.trex_util import (
    PcapList,
    TrexMode,
    get_trex_mac,
    merge_pcaps,
    mkdir_remote,
    send_to_remote,
)

logger = logging.getLogger(__name__)


class Pcap(NamedTuple):
    """A pcap to replay, with its relative weight (cps / divisor)."""

    path: Path
    weight: int | float


class BaseTrexClientManager:
    """
    Base class for creating TRex profiles.

    Subclasses are created as `MyProfile(BaseTrexClientManager, pcaps)`.

    `pcaps: PcapList` is a list of (str, int) tuples, where int is:
        - cps in STF
        - cps in ASTF
        - the divisor for `self.BASE_IPG_USEC` in STL
    """

    pcaps: PcapList
    multiplier: float | None = None
    duration: int | None = None
    _stf_config_path: Path | None = None

    BASE_IPG_USEC = 12.0  # ~1 Gbps at 1500 bytes per packet
    PCAP_PATH_PREFIX = Path(__file__).parent / "pcaps"

    def __new__(cls, *args, **kwargs) -> Self:
        if cls is BaseTrexClientManager:
            raise TypeError(
                "Do not instantiate BaseTrexClientManager, use a subclass instead"
            )
        return super().__new__(cls)

    def __init_subclass__(cls, pcaps: PcapList) -> None:
        cls.profile_pcaps = pcaps

    def __init__(
        self,
        manager: TRexManager,
        request: FixtureRequest,
        target_mac: str,
        target_vlan: int = 0,
        mode=TrexMode.ASTF,
    ) -> None:
        # self.pcaps holds (absolute local Path, weight) Pcap objects; the
        # class-level `pcaps`/`profile_pcaps` are (relative str, weight).
        self.pcaps: list[Pcap] = [
            Pcap(self.PCAP_PATH_PREFIX / p[0], p[1]) for p in self.profile_pcaps
        ]
        self.mode = mode
        self.vlan_id = target_vlan
        self.request = request
        self.multiplier: float | None = None

        # warn once per profile instead of on every run()/multiplier iteration
        if (
            request.config.getoption("--trex-stl-burst") is not None
            and mode is not TrexMode.STL
        ):
            logger.warning(
                "--trex-stl-burst is only supported in STL mode (current mode: %s). "
                "Ignoring it and using the regular duration-based replay.",
                mode.name,
            )

        if len(self.pcaps) < 1:
            raise ValueError("self.pcaps must contain at least one pcap")

        logger.info(
            "Initializing TRex client manager: mode=%s vlan_id=%d pcaps=%s",
            self.mode.name,
            self.vlan_id,
            [p.path for p in self.pcaps],
        )

        trex_gen = request.config.getoption("--trex-generator")
        trex_host = trex_gen[0].split(",")
        trex_hostname = trex_host[0]
        trex_pcie = trex_host[1]

        match self.mode:
            case TrexMode.STL:
                self.stl_generator: TRexStateless = manager.request_stateless(request)
                self.trex_version = (
                    self.stl_generator.get_handler().get_server_version()["version"]
                )

                self.stl_generator.set_dst_mac(target_mac)
                if target_vlan != 0:
                    self.stl_generator.set_vlan(target_vlan)

                parent_dir_path = self.get_remote_data_path(Path(""))
                mkdir_remote(parent_dir_path, trex_hostname)

                # Merge first, then apply the VLAN edit to the single final pcap.
                if len(self.pcaps) > 1:
                    local_paths = [p.path for p in self.pcaps]
                    weights = [float(p.weight) for p in self.pcaps]
                    # Use a per-test unique name so sequential/parallel runs don't collide.
                    merged_name = (
                        "stl_merged_"
                        + re.sub(r"[^A-Za-z0-9_.-]", "_", self.request.node.nodeid)
                        + ".pcap"
                    )
                    merged_path = merge_pcaps(
                        local_paths,
                        weights,
                        self.PCAP_PATH_PREFIX / merged_name,
                    )
                    # effective divisor = sum of weights (sources interleaved at combined rate)
                    self.pcaps = [Pcap(merged_path, sum(weights))]

                if target_vlan != 0:
                    pcap = self.pcaps[0]
                    vlan_path = Path(edit_vlan(str(pcap.path), target_vlan))
                    self.pcaps[0] = Pcap(vlan_path, pcap.weight)

                assert len(self.pcaps) == 1
                logger.info("Uploading pcap to TRex server. This might take a while.")
                pcap = self.pcaps[0]
                pcap_remote_path = self.get_remote_data_path(pcap.path)
                send_to_remote(pcap.path, trex_hostname, pcap_remote_path)

            case TrexMode.ASTF:
                self.client: TRexAdvancedStateful = manager.request_stateful(
                    request, role="client"
                )
                self.server: TRexAdvancedStateful = manager.request_stateful(
                    request, role="server"
                )
                self.trex_version = self.server.get_handler().get_server_version()[
                    "version"
                ]

                self.client.set_dst_mac(self.server.get_src_mac())
                self.server.set_dst_mac(self.client.get_src_mac())

                if target_vlan != 0:
                    self.client.set_vlan(target_vlan)
                    self.server.set_vlan(target_vlan)

            case TrexMode.STF:
                self.stf_generator = CTRexClient(trex_hostname)
                self.trex_version = self.stf_generator.get_trex_version()["Version"]

                parent_dir_path = self.get_remote_data_path(Path(""))
                mkdir_remote(parent_dir_path, trex_hostname)

                logger.info("Uploading pcaps to TRex server. This might take a while.")
                os.makedirs("tmp", exist_ok=True)
                config = ConfigBuilder(
                    "tmp/trex_cfg.yaml",
                    str(Path(__file__).parent / "default_trex.yaml"),
                )
                config.set_option("[0].interfaces", [trex_pcie, "dummy"])
                config.set_option("[0].port_info[.=dest_mac].dest_mac", target_mac)
                trex_mac_addr = get_trex_mac(
                    trex_hostname, trex_pcie, self.trex_version
                )
                config.set_option("[0].port_info[.=src_mac].src_mac", trex_mac_addr)
                if target_vlan != 0:
                    # even though port_info is an array, this syntax sets vlan on all it's items
                    config.set_option("[0].port_info.vlan", target_vlan)
                else:
                    # similarly this syntax deletes it
                    config.delete_option("[0].port_info.vlan")
                config = self.stf_config_hook(config)
                config_path = Path(config.build())
                config_remote_path = self.get_remote_data_path(config_path)
                self.remote_stf_config = config_remote_path
                send_to_remote(config_path, trex_hostname, config_remote_path)

                for i, pcap in enumerate(self.pcaps):
                    pcap_path = pcap.path
                    if target_vlan != 0:
                        pcap_path = Path(edit_vlan(str(pcap_path), target_vlan))
                    self.pcaps[i] = Pcap(pcap_path, pcap.weight)
                    pcap_remote_path = self.get_remote_data_path(pcap_path)
                    send_to_remote(pcap_path, trex_hostname, pcap_remote_path)

                profile_path = self.get_stf_profile()
                profile_remote_path = self.get_remote_data_path(profile_path)
                send_to_remote(profile_path, trex_hostname, profile_remote_path)

    def get_remote_data_path(self, local_path: Path) -> Path:
        """
        Translates `local_path` into a path on the remote TRex server.

        A directory is created from the output of `get_remote_data_path(Path(""))`.
        """
        return Path(f"/opt/trex/{self.trex_version}/pcaps") / local_path.name

    def get_astf_profile(self, multiplier: float) -> trex_astf_profile.ASTFProfile:
        """
        Returns an ASTFProfile to be loaded into TRex.
        Intended as a bridge between a native .py profile that TRex can load directly
        and a profile with multiplied CPS that is used here.
        """

        client_global_info = trex_astf_profile.ASTFGlobalInfo()
        client_global_info.ip.dont_use_inbound_mac = 1
        # https://github.com/CESNET/lbr-testsuite/blob/ab02f9fed69144e060e0bb3ad611a434b34b13cb/lbr_testsuite/trex/trex_stateful.py#L462
        client_global_info.ip.tos = 0x2

        server_global_info = trex_astf_profile.ASTFGlobalInfo()
        server_global_info.ip.dont_use_inbound_mac = 1
        server_global_info.ip.tos = 0x2

        client_ip_dist = trex_astf_profile.ASTFIPGenDist(
            ip_range=["16.0.0.0", "16.0.0.255"], distribution="seq"
        )
        server_ip_dist = trex_astf_profile.ASTFIPGenDist(
            ip_range=["48.0.0.0", "48.0.255.255"], distribution="seq"
        )
        ip_gen = trex_astf_profile.ASTFIPGen(
            dist_client=client_ip_dist, dist_server=server_ip_dist
        )

        profile = trex_astf_profile.ASTFProfile(
            default_ip_gen=ip_gen,
            cap_list=[
                trex_astf_profile.ASTFCapInfo(
                    file=str(pcap.path),
                    cps=int(multiplier * pcap.weight),
                )
                for pcap in self.pcaps
            ],
            default_c_glob_info=client_global_info,
            default_s_glob_info=server_global_info,
        )
        return profile

    def get_stf_profile(self) -> Path:
        """
        Returns the *local* path to the stateful profile config.
        The remote path is handled by `get_remote_data_path`.
        """
        if self._stf_config_path is not None:
            return self._stf_config_path

        self._stf_config_path = Path("tmp/stf_trex_profile.yaml").absolute()
        os.makedirs(self._stf_config_path.parent, exist_ok=True)
        with open(self._stf_config_path, mode="w+") as f:
            f.write("[]\n")
        profile = ConfigBuilder(str(self._stf_config_path), str(self._stf_config_path))
        profile.add_option("[0].duration", 9999)
        profile.add_option(
            "[0].generator",
            {
                "distribution": "seq",
                "clients_start": "16.0.0.1",
                "clients_end": "16.0.0.255",
                "servers_start": "48.0.0.1",
                "servers_end": "48.0.255.255",
                "clients_per_gb": 200,
                "min_clients": 100,
                "dual_port_mask": "1.0.0.0",
                "tcp_aging": 0,
                "udp_aging": 0,
            },
        )

        for i, pcap in enumerate(self.pcaps):
            trex_search_dir = f"/opt/trex/{self.trex_version}/"
            remote_pcap = str(self.get_remote_data_path(pcap.path))
            assert remote_pcap.startswith(trex_search_dir), (
                f"TRex searches for PCAPs in {trex_search_dir} and this cannot be changed"
            )
            remote_pcap = remote_pcap.removeprefix(trex_search_dir)

            profile.add_option(
                f"[0].cap_info[{i}]",
                {
                    "name": remote_pcap,
                    "cps": pcap.weight,
                    "ipg": 100,
                    "rtt": 100,
                    "w": 1,
                },
            )

        os.makedirs("tmp", exist_ok=True)
        profile.build()
        return self._stf_config_path

    def stf_config_hook(self, config: ConfigBuilder) -> ConfigBuilder:
        """
        Optionally modify the TRex config before it gets sent to the remote.
        """
        return config

    def set_props(self, multiplier: float, duration: int) -> None:
        """
        Sets the internal multiplier and duration for later use in other functions.
        """
        self.multiplier = multiplier
        self.duration = duration
        logger.debug(
            "TRex traffic properties set: multiplier=%s duration=%s",
            multiplier,
            duration,
        )

    def prepare(self) -> None:
        """
        Reset TRex instances and load profiles.
        Will raise a ValueError if `multiplier` and `duration` haven't been set with `set_props`
        """

        logger.debug("Preparing TRex traffic: mode=%s", self.mode.name)

        # pcaps are sent to the server in `__init__`

        match self.mode:
            case TrexMode.STL:
                self.stl_generator.reset()

            case TrexMode.ASTF:
                self.client.reset()
                self.server.reset()

                if self.multiplier is None or self.duration is None:
                    raise ValueError(
                        "you need to specify multiplier and duration with `set_props`"
                    )

                profile = self.get_astf_profile(self.multiplier)
                client_handler: ASTFClient = self.client.get_handler()
                server_handler: ASTFClient = self.server.get_handler()
                client_handler.load_profile(profile)
                server_handler.load_profile(profile)

            case TrexMode.STF:
                pass

    def run(
        self,
        blocking=True,
        heatup: int = 0,
        on_measurement_start: Callable[[], None] | None = None,
        run_info: RunInfo | None = None,
    ) -> None:
        """
        Start traffic from TRex and block until finished.
        Optionally only start traffic with `blocking=False`.
        Will raise a ValueError if `multiplier` and `duration` haven't been set with `set_props`

        `heatup` (seconds) and `on_measurement_start` let the caller sample
        TRex's own transmit counters at the start of the measurement window
        (after the heatup period), while traffic is actually running.

        `run_info` (optional) is used to record the actual wall-clock time TRex
        spent transmitting (e.g. the burst duration in STL exact-count mode).
        """

        logger.debug(
            "Starting TRex traffic: mode=%s multiplier=%s duration=%s blocking=%s",
            self.mode.name,
            self.multiplier,
            self.duration,
            blocking,
        )

        if self.multiplier is None or self.duration is None:
            raise ValueError(
                "you need to specify multiplier and duration with `set_props`"
            )

        def _mark_measurement_start() -> None:
            if not blocking:
                return
            if heatup > 0:
                sleep(heatup)
            if on_measurement_start is not None:
                on_measurement_start()

        burst_start: float | None = None

        match self.mode:
            case TrexMode.STL:
                client: STLClient = self.stl_generator.get_handler()
                burst = self.request.config.getoption("--trex-stl-burst")

                if burst is not None:
                    base_pps, total_pkts = burst

                    # scale rate by multiplier (binary search varies speed); packet count stays fixed
                    pps = base_pps * self.multiplier

                    if len(self.pcaps) != 1:
                        raise ValueError(
                            "--trex-stl-burst requires a single (merged) pcap; "
                            f"got {len(self.pcaps)}"
                        )
                    pcap_path = str(self.pcaps[0].path)
                    stream = STLStream(
                        name="S0",
                        packet=STLPktBuilder(pkt=pcap_path),
                        mode=STLTXSingleBurst(pps=pps, total_pkts=total_pkts),
                    )

                    client.add_streams([stream], ports=[0])
                    # burst stops on its own; -1 (unlimited) so it's never truncated at low multipliers
                    burst_start = time()
                    client.start(ports=[0], duration=-1)
                    _mark_measurement_start()
                else:
                    pcap = self.pcaps[0]
                    start = time()
                    elapsed = 0
                    while elapsed < self.duration:
                        try:
                            client.push_remote(
                                pcap_filename=str(self.get_remote_data_path(pcap.path)),
                                ports=[0],
                                ipg_usec=self.BASE_IPG_USEC / pcap.weight,
                                speedup=self.multiplier,
                                count=1,
                                duration=int(self.duration - elapsed),
                            )
                        except TRexError:
                            # wait if port was not cleared yet
                            sleep(0.05)
                        elapsed = time() - start
                        if elapsed >= heatup and on_measurement_start is not None:
                            on_measurement_start()
                            on_measurement_start = None

            case TrexMode.ASTF:
                self.server.start()
                self.client.start(duration=self.duration)
                _mark_measurement_start()

            case TrexMode.STF:
                if self.duration < 30:
                    warnings.warn(
                        UserWarning(
                            "Duration is shorter than 30 seconds, but STF mode only supports durations >= 30. Duration extended to 30s"
                        )
                    )
                    self.duration = 30

                self.stf_generator.start_trex(
                    f=str(self.get_remote_data_path(self.get_stf_profile()).absolute()),
                    d=str(self.duration),
                    m=str(self.multiplier),
                    cfg=str(self.remote_stf_config),
                )
                _mark_measurement_start()

        if blocking:
            self.wait_on_traffic()

        # measure actual burst duration (burst stops on its own once count is sent)
        if burst_start is not None and run_info is not None:
            run_info.transmit_seconds = time() - burst_start

        logger.debug("TRex traffic finished")

    def wait_on_traffic(self) -> None:
        match self.mode:
            case TrexMode.STL:
                self.stl_generator.wait_on_traffic()

            case TrexMode.ASTF:
                self.client.wait_on_traffic()
                self.server.stop()

            case TrexMode.STF:
                assert self.duration is not None
                start = time()
                while (
                    self.stf_generator.is_running() and time() - start < self.duration
                ):
                    sleep(1)
                self.stop()

    def stop(self) -> None:
        logger.info("Stopping TRex traffic: mode=%s", self.mode.name)
        match self.mode:
            case TrexMode.STL:
                self.stl_generator.stop()

            case TrexMode.ASTF:
                self.server.stop()

            case TrexMode.STF:
                if self.stf_generator.is_running():
                    self.stf_generator.stop_trex()

    def update_runinfo(self, run_info: RunInfo) -> None:
        """
        Alternative to `get_stats` so that the API is independent of the used TRex mode.
        """
        logger.debug("Updating run info from TRex stats")
        match self.mode:
            case TrexMode.STL:
                run_info.trex_server_stats = self.get_stats()
                run_info.trex_client_stats = None
            case TrexMode.ASTF:
                run_info.trex_client_stats = self.client.get_stats()
                run_info.trex_server_stats = self.server.get_stats()
            case TrexMode.STF:
                run_info.trex_server_stats = self.get_stats()
                run_info.trex_client_stats = None

        run_info.trex_pretty_stats["opackets"] = self.get_tx_packets()
        run_info.trex_pretty_stats["obytes"] = self.get_tx_bytes()

    def get_tx_packets(self) -> int:
        """Current cumulative TRex transmit packet count."""
        match self.mode:
            case TrexMode.STL:
                return int(self.stl_generator.get_stats()["total"]["opackets"])
            case TrexMode.ASTF:
                return int(self.server.get_stats()["total"]["opackets"]) + int(
                    self.client.get_stats()["total"]["opackets"]
                )
            case TrexMode.STF:
                data = self.stf_generator.get_result_obj().get_latest_dump()[
                    "trex-global"
                ]["data"]
                return int(data["m_total_tx_pkts"])

    def get_tx_bytes(self) -> int:
        """Current cumulative TRex transmit byte count."""
        match self.mode:
            case TrexMode.STL:
                return int(self.stl_generator.get_stats()["total"]["obytes"])
            case TrexMode.ASTF:
                return int(self.server.get_stats()["total"]["obytes"]) + int(
                    self.client.get_stats()["total"]["obytes"]
                )
            case TrexMode.STF:
                data = self.stf_generator.get_result_obj().get_latest_dump()[
                    "trex-global"
                ]["data"]
                return int(data["m_total_tx_bytes"])

    def get_stats(self, role: Literal["server"] | Literal["client"] = "server") -> Dict:
        assert role in ("server", "client")

        match self.mode:
            case TrexMode.STL:
                return self.stl_generator.get_stats()

            case TrexMode.ASTF:
                if role == "server":
                    return self.server.get_stats()
                elif role == "client":
                    return self.client.get_stats()

            case TrexMode.STF:
                return self.stf_generator.get_result_obj().get_latest_dump()


class BaseAdHocTrex(BaseTrexClientManager, pcaps=[]):
    """
    Base class for ad-hoc TRex profiles that take their pcaps at runtime
    (rather than at class definition time).

    All ad-hoc profiles share the same `__init__` so they behave consistently.
    """

    def __init__(
        self,
        pcaps: PcapList,
        manager: TRexManager,
        request: FixtureRequest,
        target_mac: str,
        target_vlan: int = 0,
        mode: TrexMode = TrexMode.STL,
    ):
        self.profile_pcaps = pcaps
        super().__init__(manager, request, target_mac, target_vlan, mode=mode)
