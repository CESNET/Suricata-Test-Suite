"""
Author(s):  Matyáš Sedmidubský <matyas.sedmidubsky@cesnet.cz>

Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause
"""

import logging
import os
import subprocess
from enum import Enum
from pathlib import Path
from typing import Sequence, Tuple

import pytest
from lbr_testsuite.executable import executable, remote_executor

logger = logging.getLogger(__name__)


class TrexMode(Enum):
    STL = 0
    ASTF = 1
    STF = 2


PcapList = Sequence[Tuple[str, int | float]]


def _packet_generator(
    pcap_paths: list[Path],
    per_round: list[int],
    restart: bool,
):
    """
    Yields packets from `pcap_paths` following weighted round-robin rules.

    Each source emits `per_round[i]` packets per round. When `restart` is
    True, an exhausted source is restarted from the beginning so it keeps
    contributing proportionally for as long as the merge runs; otherwise it
    is marked empty and skipped. Stops once every source is empty.

    Readers are opened here and always closed (including on error), so the
    caller does not need to manage them.
    """
    from scapy.all import PcapReader

    readers = []
    try:
        for p in pcap_paths:
            readers.append(PcapReader(str(p)))
    except Exception:
        for r in readers:
            r.close()
        raise
    iters = [iter(r) for r in readers]
    empty = [False] * len(iters)
    try:
        while not all(empty):
            for si, it in enumerate(iters):
                if empty[si]:
                    continue
                for _ in range(per_round[si]):
                    try:
                        pkt = next(it)
                    except StopIteration:
                        if not restart:
                            # no cap: merge each source exactly once
                            empty[si] = True
                            break
                        # restart exhausted stream to keep it contributing proportionally
                        readers[si].close()
                        readers[si] = PcapReader(str(pcap_paths[si]))
                        iters[si] = iter(readers[si])
                        # read the rest of this round from the fresh reader
                        it = iters[si]
                        try:
                            pkt = next(it)
                        except StopIteration:
                            # empty pcap: nothing to contribute, skip it
                            empty[si] = True
                            break
                    yield pkt
    finally:
        for r in readers:
            r.close()


def merge_pcaps(
    pcap_paths: list[Path],
    weights: list[float],
    out_path: Path,
    max_packets: int | None = None,
) -> Path:
    """
    Merges several pcaps into one by interleaving their packets
    proportionally to `weights` (weighted round-robin).

    Packets are read and written one at a time (streaming) so that large
    pcaps are not loaded fully into memory.

    When `max_packets` is set, a short pcap with a large weight would
    otherwise be exhausted quickly and become under-represented relative to
    its expected weight. To avoid this, exhausted streams are restarted
    (looped back to the beginning) so every source keeps contributing
    proportionally for as long as the merge runs (up to the `max_packets`
    cap). The output reaches `max_packets` only if there are enough packets;
    otherwise it stops early once every source is exhausted.

    When `max_packets` is `None` (default), no cap is applied: each source is
    merged exactly once and the merge stops when every source is exhausted.

    Returns `out_path` with the merged pcap written.
    """
    from scapy.all import PcapWriter

    if not pcap_paths:
        raise ValueError("pcap_paths must not be empty")
    if len(pcap_paths) != len(weights):
        raise ValueError("pcap_paths and weights must have the same length")
    if any(w <= 0 for w in weights):
        raise ValueError("all weights must be positive")
    if max_packets is not None and max_packets <= 0:
        raise ValueError("max_packets must be positive")

    total_w = sum(weights)
    if total_w <= 0:
        raise ValueError("sum of weights must be positive")

    # weighted round-robin: per-round packet count proportional to weight share
    quotas = [w / total_w for w in weights]
    min_q = min(q for q in quotas if q > 0)
    # each source emits at least 1 packet per round
    per_round = [max(1, round(q / min_q)) for q in quotas]

    out_path.parent.mkdir(parents=True, exist_ok=True)

    total = 0
    with PcapWriter(str(out_path), append=False, sync=True) as writer:
        for pkt in _packet_generator(
            pcap_paths, per_round, restart=max_packets is not None
        ):
            if max_packets is not None and total >= max_packets:
                break
            writer.write(pkt)
            total += 1

    logger.info(
        "Merged %d pcaps into %s (%d packets, weights=%s)",
        len(pcap_paths),
        out_path.name,
        total,
        weights,
    )
    return out_path


def send_to_remote(source: Path, hostname: str, destination: Path | None = None):
    if destination is None:
        destination = source

    logger.debug("Sending %s to remote %s:%s", source, hostname, destination)
    subprocess.run(
        [
            "rsync",
            "-z",
            "--checksum",
            "--update",
            str(source),
            f"{os.environ['USER']}@{hostname}:{str(destination)}",
        ],
        check=True,
    )


def mkdir_remote(dir: Path, hostname: str):
    logger.debug("Creating remote directory %s on %s", dir, hostname)
    executor = remote_executor.RemoteExecutor(host=hostname, user=os.environ["USER"])
    mkdir = executable.Tool(
        f"mkdir -p '{str(dir)}' && chmod 777 '{str(dir)}'",
        executor=executor,
        sudo=True,
    )
    mkdir.run()


def get_trex_mac(hostname: str, pci: str, trex_version: str):
    logger.debug(
        "Getting TRex MAC for %s on %s (version %s)", pci, hostname, trex_version
    )
    executor = remote_executor.RemoteExecutor(host=hostname, user=os.environ["USER"])
    get_mac = executable.Tool(
        f"cd /opt/trex/{trex_version} && ./dpdk_setup_ports.py -t | grep {pci[5:]} | awk '{{print $8}}'",
        executor=executor,
        sudo=True,
    )
    stdout, _ = get_mac.run()

    stdout = str(stdout).strip()
    assert len(stdout) == 17, f"Couldn't get MAC address for {pci}"
    logger.debug("TRex MAC for %s: %s", pci, stdout)
    return stdout


def str_to_trex_mode(mode: str) -> TrexMode | None:
    match mode.lower():
        case "astf":
            return TrexMode.ASTF
        case "stf":
            return TrexMode.STF
        case "stl":
            return TrexMode.STL
        case _:
            return None


def get_trex_mode(request, available_modes) -> TrexMode:
    """
    Selects a TRex mode out of `available_modes` based on the
    `--prefer-trex-mode` and `--force-trex-mode` flags.

    `available_modes: List[TrexMode]` should be in descending order by priority.

    Automatically skips tests with no usable TRex modes.
    """
    if (
        not isinstance(available_modes, list)
        or len(available_modes) < 1
        or not isinstance(available_modes[0], TrexMode)
    ):
        raise ValueError("available_modes must be a list of at least one TrexMode")

    forced_mode = request.config.getoption("--force-trex-mode")
    if forced_mode is not None:
        mode_enum = str_to_trex_mode(forced_mode)
        if mode_enum is None:
            raise ValueError(f"{forced_mode} is not a valid TRex mode")

        if mode_enum in available_modes:
            logger.debug("Using forced TRex mode: %s", forced_mode)
            return mode_enum
        else:
            pytest.skip(f"{forced_mode} is not supported by this test")

    preferred_mode = request.config.getoption("--prefer-trex-mode")
    if preferred_mode is not None:
        mode_enum = str_to_trex_mode(preferred_mode)
        if mode_enum is None:
            raise ValueError(f"{preferred_mode} is not a valid TRex mode")

        if mode_enum in available_modes:
            logger.debug("Using preferred TRex mode: %s", preferred_mode)
            return mode_enum
        else:
            logger.debug(
                "Preferred TRex mode %s unavailable, falling back to %s",
                preferred_mode,
                available_modes[0].name,
            )
            return available_modes[0]

    logger.debug("Using default TRex mode: %s", available_modes[0].name)
    return available_modes[0]
