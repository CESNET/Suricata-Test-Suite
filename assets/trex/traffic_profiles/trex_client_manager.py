"""
Author(s):  Matyáš Sedmidubský <matyas.sedmidubsky@cesnet.cz>

Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

TRex profile template for use in Suricata-Test-Suite
"""

import logging
import warnings
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from time import sleep, time
from typing import (
    Any,
    ClassVar,
    Literal,
    NamedTuple,
    ParamSpec,
    Self,
    TypeVar,
    assert_never,
    cast,
)

from lbr_testsuite.trex import (
    TRexAdvancedStateful,
    TRexManager,
    TRexStateless,
)
from pytest import FixtureRequest

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
from trex_client import CTRexClient

from conftest import fmt_bytes, fmt_thousands
from util.add_vlan import edit_vlan
from util.cache_util import cache_path, try_cache
from util.config_builder import DEFAULT_TREX_CONF, ConfigBuilder
from util.suri_util import RunInfo
from util.trex_util import (
    TrexMode,
    get_merged_pcap,
    get_trex_mac,
    mkdir_remote,
    send_to_remote,
)

logger = logging.getLogger(__name__)


class Pcap(NamedTuple):
    """A pcap to replay, with its relative weight (cps / divisor)."""

    path: Path
    weight: int | float


@dataclass(frozen=True, slots=True)
class TRexRequest:
    """Immutable request-time configuration for a TRex run.

    Built once in ``BaseTrexClientManager.__init__`` from pytest options;
    no code outside ``__init__`` should parse request options.
    """

    mode: TrexMode
    hostname: str
    pcie: str
    burst: tuple[float, int] | None
    force_pcap_upload: bool


@dataclass(frozen=True, slots=True)
class StlState:
    """Session handles for STL mode."""

    generator: TRexStateless
    remote_pcap: Path


@dataclass(frozen=True, slots=True)
class AstfState:
    """Session handles for ASTF mode."""

    client: TRexAdvancedStateful
    server: TRexAdvancedStateful


@dataclass(frozen=True, slots=True)
class StfState:
    """Session handles for STF mode."""

    generator: CTRexClient
    remote_config: Path
    remote_profile: Path


_P = ParamSpec("_P")
_R = TypeVar("_R")


def switch_on_mode(
    mode: TrexMode,
    stl: Callable[_P, _R],
    astf: Callable[_P, _R],
    stf: Callable[_P, _R],
    /,
    *args: _P.args,
    **kwargs: _P.kwargs,
) -> _R:
    """
    Dispatch to the mode-specific function selected by `mode`.

    All three functions must share a single signature; `args` and `kwargs`
    are forwarded to the selected one.
    """
    match mode:
        case TrexMode.STL:
            return stl(*args, **kwargs)
        case TrexMode.ASTF:
            return astf(*args, **kwargs)
        case TrexMode.STF:
            return stf(*args, **kwargs)
        case _:
            assert_never(mode)


class BaseTrexClientManager:
    """
    Base class for creating TRex profiles.

    Subclasses are created as `MyProfile(BaseTrexClientManager, pcaps=...)`,
    where `pcaps` is a list of `Pcap` objects with paths relative to
    `PCAP_PATH_PREFIX`. The weight is:
        - cps in STF
        - cps in ASTF
        - the divisor for `self.BASE_IPG_USEC` in STL
    """

    pcaps: list[Pcap]
    profile_pcaps: ClassVar[list[Pcap]] = []
    multiplier: float = 1.0
    duration: int
    # set by the `_init_*` dispatch at the end of `__init__`
    trex_version: str  # pyright: ignore[reportUninitializedInstanceVariable]
    _state: StlState | AstfState | StfState

    BASE_IPG_USEC = 12.0  # ~1 Gbps at 1500 bytes per packet
    PCAP_PATH_PREFIX = Path(__file__).parent / "pcaps"

    def __new__(cls, *args, **kwargs) -> Self:
        if cls is BaseTrexClientManager:
            raise TypeError(
                "Do not instantiate BaseTrexClientManager, use a subclass instead"
            )
        return super().__new__(cls)

    def __init_subclass__(cls, pcaps: list[Pcap]) -> None:
        cls.profile_pcaps = pcaps

    def __init__(
        self,
        manager: TRexManager,
        request: FixtureRequest,
        target_mac: str,
        target_vlan: int = 0,
        mode: TrexMode = TrexMode.ASTF,
    ) -> None:
        trex_gen = request.config.getoption("--trex-generator")
        assert trex_gen is not None
        hostname, pcie = trex_gen[0].split(",")

        self.trex_request = TRexRequest(
            mode=mode,
            hostname=hostname,
            pcie=pcie,
            burst=cast(
                "tuple[float, int] | None",
                request.config.getoption("--trex-stl-burst"),
            ),
            force_pcap_upload=cast(
                bool, request.config.getoption("--force-pcap-upload")
            ),
        )

        self.duration = cast(int, request.config.getoption("--traffic-duration"))

        # warn once per profile instead of on every run()/multiplier iteration
        if self.trex_request.burst is not None and mode is not TrexMode.STL:
            logger.warning(
                "--trex-stl-burst is only supported in STL mode (current mode: %s). "
                "Ignoring it and using the regular duration-based replay.",
                mode.name,
            )

        # `profile_pcaps` hold paths relative to PCAP_PATH_PREFIX;
        # self.pcaps holds absolute local paths.
        self.pcaps = [
            Pcap(self.PCAP_PATH_PREFIX / p.path, p.weight) for p in self.profile_pcaps
        ]

        if len(self.pcaps) < 1:
            raise ValueError("self.pcaps must contain at least one pcap")

        logger.info(
            "Initializing TRex client manager: mode=%s vlan_id=%d pcaps=%s",
            mode.name,
            target_vlan,
            [str(p.path.relative_to(self.PCAP_PATH_PREFIX)) for p in self.pcaps],
        )

        self._state = switch_on_mode(
            mode,
            self._init_stl,
            self._init_astf,
            self._init_stf,
            manager=manager,
            request=request,
            target_mac=target_mac,
            target_vlan=target_vlan,
        )

    # --- mode-specific initialization -------------------------------------

    def _init_stl(
        self,
        manager: TRexManager,
        request: FixtureRequest,
        target_mac: str,
        target_vlan: int,
    ) -> StlState:
        stl_generator = cast(TRexStateless, manager.request_stateless(request))
        self.trex_version = (
            stl_generator.get_handler().get_server_version()["version"]  # pyright: ignore[reportOptionalMemberAccess]
        )

        stl_generator.set_dst_mac(target_mac)
        if target_vlan != 0:
            stl_generator.set_vlan(target_vlan)

        parent_dir_path = self.get_remote_data_path(Path(""))
        mkdir_remote(parent_dir_path, self.trex_request.hostname)

        # Merge first, then apply the VLAN edit to the single final pcap.
        if len(self.pcaps) > 1:
            local_paths = [p.path for p in self.pcaps]
            weights = [float(p.weight) for p in self.pcaps]
            merged_path = get_merged_pcap(local_paths, weights)
            self.pcaps = [Pcap(merged_path, sum(weights))]

        assert len(self.pcaps) == 1
        pcap = self.pcaps[0]

        if target_vlan != 0:
            vlan_path = Path(edit_vlan(str(pcap.path), target_vlan))
            self.pcaps = [Pcap(vlan_path, pcap.weight)]
            pcap = self.pcaps[0]

        logger.info("Uploading pcap to TRex server. This might take a while.")
        pcap_remote_path = self.get_remote_data_path(pcap.path)
        send_to_remote(
            pcap.path,
            self.trex_request.hostname,
            pcap_remote_path,
            force=self.trex_request.force_pcap_upload,
        )

        return StlState(generator=stl_generator, remote_pcap=pcap_remote_path)

    def _init_astf(
        self,
        manager: TRexManager,
        request: FixtureRequest,
        target_mac: str,
        target_vlan: int,
    ) -> AstfState:
        client = cast(
            TRexAdvancedStateful,
            manager.request_stateful(request, role="client"),
        )
        server = cast(
            TRexAdvancedStateful,
            manager.request_stateful(request, role="server"),
        )
        self.trex_version = server.get_handler().get_server_version()[  # pyright: ignore[reportOptionalMemberAccess]
            "version"
        ]

        client.set_dst_mac(server.get_src_mac())
        server.set_dst_mac(client.get_src_mac())

        if target_vlan != 0:
            client.set_vlan(target_vlan)
            server.set_vlan(target_vlan)

        return AstfState(client=client, server=server)

    def _init_stf(
        self,
        manager: TRexManager,
        request: FixtureRequest,
        target_mac: str,
        target_vlan: int,
    ) -> StfState:
        stf_generator = CTRexClient(self.trex_request.hostname)
        self.trex_version = stf_generator.get_trex_version()["Version"]

        parent_dir_path = self.get_remote_data_path(Path(""))
        mkdir_remote(parent_dir_path, self.trex_request.hostname)

        logger.info("Uploading pcaps to TRex server. This might take a while.")
        config_path = self._build_stf_config(target_mac, target_vlan)
        config_remote_path = self.get_remote_data_path(config_path)
        force_upload = self.trex_request.force_pcap_upload
        send_to_remote(
            config_path,
            self.trex_request.hostname,
            config_remote_path,
            force=force_upload,
        )

        vlanned_pcaps: list[Pcap] = []
        for pcap in self.pcaps:
            pcap_path = pcap.path
            if target_vlan != 0:
                pcap_path = Path(edit_vlan(str(pcap_path), target_vlan))
            vlanned_pcaps.append(Pcap(pcap_path, pcap.weight))
            pcap_remote_path = self.get_remote_data_path(pcap_path)
            send_to_remote(
                pcap_path,
                self.trex_request.hostname,
                pcap_remote_path,
                force=force_upload,
            )
        self.pcaps = vlanned_pcaps

        profile_path = self.get_stf_profile()
        profile_remote_path = self.get_remote_data_path(profile_path)
        send_to_remote(
            profile_path,
            self.trex_request.hostname,
            profile_remote_path,
            force=force_upload,
        )

        return StfState(
            generator=stf_generator,
            remote_config=config_remote_path,
            remote_profile=profile_remote_path,
        )

    def _build_stf_config(self, target_mac: str, target_vlan: int) -> Path:
        """Build the platform config and return its local path."""
        config = ConfigBuilder(
            str(cache_path("trex_cfg.yaml", persistent=False)),
            str(DEFAULT_TREX_CONF),
        )
        config.set_option("[0].interfaces", [self.trex_request.pcie, "dummy"])
        config.set_option("[0].port_info[.=dest_mac].dest_mac", target_mac)
        trex_mac_addr = get_trex_mac(
            self.trex_request.hostname,
            self.trex_request.pcie,
            self.trex_version,
        )
        config.set_option("[0].port_info[.=src_mac].src_mac", trex_mac_addr)
        if target_vlan != 0:
            # even though port_info is an array, this syntax sets vlan on all it's items
            config.set_option("[0].port_info.vlan", target_vlan)
        else:
            # similarly this syntax deletes it
            config.delete_option("[0].port_info.vlan")
        config = self.stf_config_hook(config)
        return Path(config.build())

    # --- mode state access ------------------------------------------------

    @property
    def _stl(self) -> StlState:
        state = self._state
        if not isinstance(state, StlState):
            raise TypeError(f"STL state accessed in {self.trex_request.mode.name} mode")
        return state

    @property
    def _astf(self) -> AstfState:
        state = self._state
        if not isinstance(state, AstfState):
            raise TypeError(
                f"ASTF state accessed in {self.trex_request.mode.name} mode"
            )
        return state

    @property
    def _stf(self) -> StfState:
        state = self._state
        if not isinstance(state, StfState):
            raise TypeError(f"STF state accessed in {self.trex_request.mode.name} mode")
        return state

    # --- profile builders -------------------------------------------------

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

        The profile is cached under `.cache/persistent/` under a name derived
        from its inputs (pcap names and weights), so it is only regenerated when
        the inputs change; delete `.cache/` to force regeneration.
        """
        key_parts: list[object] = [str(p.path.name) for p in self.pcaps]
        key_parts += [str(p.weight) for p in self.pcaps]

        profile_path = try_cache("stf_profile.yaml", key_parts)
        if profile_path is not None:
            return profile_path

        profile_path = cache_path("stf_profile.yaml", *key_parts)
        with open(profile_path, mode="w+") as f:
            f.write("[]\n")
        profile = ConfigBuilder(str(profile_path), str(profile_path))
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

        profile.build()
        return profile_path

    def stf_config_hook(self, config: ConfigBuilder) -> ConfigBuilder:
        """
        Optionally modify the TRex config before it gets sent to the remote.
        """
        return config

    # --- traffic lifecycle: props, prepare, run, wait, stop ---------------

    def prepare(self) -> None:
        """
        Reset TRex instances and load profiles.
        """

        logger.debug("Preparing TRex traffic: mode=%s", self.trex_request.mode.name)

        # pcaps are sent to the server in `__init__`

        switch_on_mode(
            self.trex_request.mode,
            self._stl_prepare,
            self._astf_prepare,
            self._stf_prepare,
        )

    def _stl_prepare(self) -> None:
        self._stl.generator.reset()

    def _astf_prepare(self) -> None:
        self._astf.client.reset()
        self._astf.server.reset()

        profile = self.get_astf_profile(self.multiplier)
        client_handler = cast(ASTFClient, self._astf.client.get_handler())
        server_handler = cast(ASTFClient, self._astf.server.get_handler())
        client_handler.load_profile(profile)
        server_handler.load_profile(profile)

    def _stf_prepare(self) -> None:
        pass

    def run(
        self,
        blocking: bool = True,
        heatup: int = 0,
        on_measurement_start: Callable[[], None] | None = None,
        run_info: RunInfo | None = None,
    ) -> None:
        """
        Start traffic from TRex and block until finished.
        Optionally only start traffic with `blocking=False`.

        `heatup` (seconds) and `on_measurement_start` let the caller sample
        TRex's own transmit counters at the start of the measurement window
        (after the heatup period), while traffic is actually running.

        `run_info` (optional) is used to record the actual wall-clock time TRex
        spent transmitting (e.g. the burst duration in STL exact-count mode).
        """

        logger.debug(
            "Starting TRex traffic: mode=%s multiplier=%s duration=%s blocking=%s",
            self.trex_request.mode.name,
            self.multiplier,
            self.duration,
            blocking,
        )

        burst_start = switch_on_mode(
            self.trex_request.mode,
            self._stl_run,
            self._astf_run,
            self._stf_run,
            blocking=blocking,
            heatup=heatup,
            on_measurement_start=on_measurement_start,
            run_info=run_info,
        )

        if blocking:
            self.wait_on_traffic()

        if burst_start is not None and run_info is not None:
            run_info.transmit_seconds = time() - burst_start

        logger.debug("TRex traffic finished")

    def _mark_measurement_start(
        self,
        blocking: bool,
        heatup: int,
        on_measurement_start: Callable[[], None] | None,
    ) -> None:
        if not blocking:
            return
        if heatup > 0:
            sleep(heatup)
        if on_measurement_start is not None:
            on_measurement_start()

    def _stl_run(
        self,
        *,
        blocking: bool,
        heatup: int,
        on_measurement_start: Callable[[], None] | None,
        run_info: RunInfo | None,
    ) -> float | None:
        """
        Start STL traffic. Returns the burst start timestamp in exact-count
        burst mode, `None` otherwise.
        """
        client = cast(STLClient, self._stl.generator.get_handler())
        burst = self.trex_request.burst

        if burst is not None:
            return self._stl_run_burst(
                client,
                burst,
                blocking=blocking,
                heatup=heatup,
                on_measurement_start=on_measurement_start,
                run_info=run_info,
            )
        self._stl_run_duration(
            client, heatup=heatup, on_measurement_start=on_measurement_start
        )
        return None

    def _stl_run_burst(
        self,
        client: STLClient,
        burst: tuple[float, int],
        *,
        blocking: bool,
        heatup: int,
        on_measurement_start: Callable[[], None] | None,
        run_info: RunInfo | None,
    ) -> float | None:
        """
        Replay an exact packet count at a fixed rate. Returns the burst start
        timestamp.
        """
        base_pps, total_pkts = burst

        # scale rate by multiplier (binary search varies speed); packet count stays fixed
        pps = base_pps * self.multiplier

        if len(self.pcaps) != 1:
            raise ValueError(
                "--trex-stl-burst requires a single (merged) pcap; "
                f"got {len(self.pcaps)}"
            )
        pcap = self.pcaps[0]
        burst_duration = total_pkts / pps if pps > 0 else 0.0
        burst_start = time()
        client.push_remote(
            pcap_filename=str(self.get_remote_data_path(pcap.path)),
            ports=[0],
            ipg_usec=1e6 / base_pps,
            speedup=self.multiplier,
            count=0,
            duration=burst_duration,
        )
        if blocking and on_measurement_start is not None:
            if heatup > 0 and burst_duration > 0:
                sleep(min(heatup, burst_duration))
            on_measurement_start()
        if run_info is not None:
            self._sample_burst_pps(
                run_info,
                burst_start=burst_start,
                burst_duration=burst_duration,
                pps=pps,
            )
        return burst_start

    def _sample_burst_pps(
        self,
        run_info: RunInfo,
        *,
        burst_start: float,
        burst_duration: float,
        pps: float,
    ) -> None:
        """Sample TRex's own tx rate at fractions of the burst duration."""
        sample_fracs = (0.10, 0.35, 0.65, 0.90)
        samples: list[float] = []
        for frac in sample_fracs:
            target = burst_start + burst_duration * frac
            remaining = target - time()
            if remaining > 0:
                sleep(remaining)
            samples.append(self.get_tx_pps())
        run_info.trex_tx_pps_at_start = samples[0]
        run_info.trex_tx_pps_samples = samples
        logger.debug(
            "Mid-burst tx rate samples: %s pps (expected %.2f pps, multiplier %s)",
            ", ".join(f"{s:.2f}" for s in samples),
            pps,
            self.multiplier,
        )

    def _stl_run_duration(
        self,
        client: STLClient,
        *,
        heatup: int,
        on_measurement_start: Callable[[], None] | None,
    ) -> None:
        """Replay the pcap in a loop for `self.duration` seconds."""
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

    def _astf_run(
        self,
        *,
        blocking: bool,
        heatup: int,
        on_measurement_start: Callable[[], None] | None,
        run_info: RunInfo | None,
    ) -> float | None:
        self._astf.server.start()
        self._astf.client.start(duration=self.duration)
        self._mark_measurement_start(blocking, heatup, on_measurement_start)
        return None

    def _stf_run(
        self,
        *,
        blocking: bool,
        heatup: int,
        on_measurement_start: Callable[[], None] | None,
        run_info: RunInfo | None,
    ) -> float | None:
        duration = self.duration
        if duration < 30:
            warnings.warn(
                UserWarning(
                    "Duration is shorter than 30 seconds, but STF mode only supports durations >= 30. Duration extended to 30s"
                )
            )
            duration = 30

        self._stf.generator.start_trex(
            f=str(self._stf.remote_profile),
            d=str(duration),
            m=str(self.multiplier),
            cfg=str(self._stf.remote_config),
        )
        self._mark_measurement_start(blocking, heatup, on_measurement_start)
        return None

    def wait_on_traffic(self) -> None:
        """
        Block until all traffic has been sent and stop the TRex generators.
        """
        switch_on_mode(
            self.trex_request.mode,
            self._stl_wait_on_traffic,
            self._astf_wait_on_traffic,
            self._stf_wait_on_traffic,
        )

    def _stl_wait_on_traffic(self) -> None:
        self._stl.generator.wait_on_traffic()
        self.stop()

    def _astf_wait_on_traffic(self) -> None:
        self._astf.client.wait_on_traffic()
        self.stop()

    def _stf_wait_on_traffic(self) -> None:
        start = time()
        while self._stf.generator.is_running() and time() - start < self.duration:
            sleep(1)
        self.stop()

    def stop(self) -> None:
        """
        Stop the TRex generators and log the transmitted packet/byte counts.
        """
        logger.info(
            "Stopping TRex traffic (%s, %s pkts, %s)",
            self.trex_request.mode.name,
            fmt_thousands(self.get_tx_packets()),
            fmt_bytes(self.get_tx_bytes()),
        )
        switch_on_mode(
            self.trex_request.mode,
            self._stl_stop,
            self._astf_stop,
            self._stf_stop,
        )

    def _stl_stop(self) -> None:
        self._stl.generator.stop()

    def _astf_stop(self) -> None:
        self._astf.server.stop()

    def _stf_stop(self) -> None:
        if self._stf.generator.is_running():
            self._stf.generator.stop_trex()

    # --- stats ------------------------------------------------------------

    def update_runinfo(self, run_info: RunInfo) -> None:
        """
        Alternative to `get_stats` so that the API is independent of the used TRex mode.
        """
        logger.debug("Updating run info from TRex stats")
        switch_on_mode(
            self.trex_request.mode,
            self._stl_update_runinfo,
            self._astf_update_runinfo,
            self._stf_update_runinfo,
            run_info=run_info,
        )

        run_info.trex_pretty_stats["opackets"] = self.get_tx_packets()
        run_info.trex_pretty_stats["obytes"] = self.get_tx_bytes()

    def _stl_update_runinfo(self, run_info: RunInfo) -> None:
        run_info.trex_server_stats = self.get_stats()
        run_info.trex_client_stats = None

    def _astf_update_runinfo(self, run_info: RunInfo) -> None:
        run_info.trex_client_stats = self._astf.client.get_stats()
        run_info.trex_server_stats = self._astf.server.get_stats()

    def _stf_update_runinfo(self, run_info: RunInfo) -> None:
        run_info.trex_server_stats = self.get_stats()
        run_info.trex_client_stats = None

    def get_tx_packets(self) -> int:
        """Current cumulative TRex transmit packet count."""
        return int(
            switch_on_mode(
                self.trex_request.mode,
                self._stl_tx_packets,
                self._astf_tx_packets,
                self._stf_tx_packets,
            )
        )

    def _stl_tx_packets(self) -> float:
        return float(
            self._stl.generator.get_stats().get("total", {}).get("opackets", 0)
        )

    def _astf_tx_packets(self) -> float:
        return float(
            self._astf.server.get_stats().get("total", {}).get("opackets", 0)
        ) + float(self._astf.client.get_stats().get("total", {}).get("opackets", 0))

    def _stf_tx_packets(self) -> float:
        return float(
            self._stf.generator.get_result_obj()
            .get_latest_dump()
            .get("trex-global", {})
            .get("data", {})
            .get("m_total_tx_pkts", 0)
        )

    def get_tx_bytes(self) -> int:
        """Current cumulative TRex transmit byte count."""
        return int(
            switch_on_mode(
                self.trex_request.mode,
                self._stl_tx_bytes,
                self._astf_tx_bytes,
                self._stf_tx_bytes,
            )
        )

    def _stl_tx_bytes(self) -> float:
        return float(self._stl.generator.get_stats().get("total", {}).get("obytes", 0))

    def _astf_tx_bytes(self) -> float:
        return float(
            self._astf.server.get_stats().get("total", {}).get("obytes", 0)
        ) + float(self._astf.client.get_stats().get("total", {}).get("obytes", 0))

    def _stf_tx_bytes(self) -> float:
        return float(
            self._stf.generator.get_result_obj()
            .get_latest_dump()
            .get("trex-global", {})
            .get("data", {})
            .get("m_total_tx_bytes", 0)
        )

    def get_tx_pps(self) -> float:
        """Current instantaneous TRex transmit rate (packets per second).

        This is TRex's own reported rate (`tx_pps`), sampled at the moment of
        the call. It is an instantaneous snapshot, not an average over the
        burst, so it should be sampled while traffic is actively running to be
        meaningful.
        """
        return switch_on_mode(
            self.trex_request.mode,
            self._stl_tx_pps,
            self._astf_tx_pps,
            self._stf_tx_pps,
        )

    def _stl_tx_pps(self) -> float:
        return float(
            self._stl.generator.get_stats().get("total", {}).get("tx_pps", 0.0)
        )

    def _astf_tx_pps(self) -> float:
        return float(
            self._astf.server.get_stats().get("total", {}).get("tx_pps", 0.0)
        ) + float(self._astf.client.get_stats().get("total", {}).get("tx_pps", 0.0))

    def _stf_tx_pps(self) -> float:
        return float(
            self._stf.generator.get_result_obj()
            .get_latest_dump()
            .get("trex-global", {})
            .get("data", {})
            .get("m_tx_pps", 0.0)
        )

    def get_stats(self, role: Literal["server", "client"] = "server") -> dict[str, Any]:
        """
        Raw statistics reported by the TRex generator.

        `role` only applies to ASTF mode, which has separate client and
        server instances; in STL/STF it is ignored.
        """
        assert role in ("server", "client")

        return switch_on_mode(
            self.trex_request.mode,
            self._stl_stats,
            self._astf_stats,
            self._stf_stats,
            role=role,
        )

    def _stl_stats(self, role: Literal["server", "client"]) -> dict[str, Any]:
        return self._stl.generator.get_stats()

    def _astf_stats(self, role: Literal["server", "client"]) -> dict[str, Any]:
        assert role in ("server", "client")
        if role == "server":
            return self._astf.server.get_stats()
        return self._astf.client.get_stats()

    def _stf_stats(self, role: Literal["server", "client"]) -> dict[str, Any]:
        return self._stf.generator.get_result_obj().get_latest_dump()


class BaseAdHocTrex(BaseTrexClientManager, pcaps=[]):
    """
    Base class for ad-hoc TRex profiles that take their pcaps at runtime
    (rather than at class definition time).

    All ad-hoc profiles share the same `__init__` so they behave consistently.
    """

    def __init__(
        self,
        pcaps: list[Pcap],
        manager: TRexManager,
        request: FixtureRequest,
        target_mac: str,
        target_vlan: int = 0,
        mode: TrexMode = TrexMode.STL,
    ):
        self.__class__.profile_pcaps = pcaps
        super().__init__(manager, request, target_mac, target_vlan, mode=mode)
