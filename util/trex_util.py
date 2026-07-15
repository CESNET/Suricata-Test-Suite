"""
Author(s):  Matyáš Sedmidubský <matyas.sedmidubsky@cesnet.cz>

Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause
"""

import os
import subprocess
from enum import Enum
from pathlib import Path
from typing import Sequence, Tuple

import pytest
from lbr_testsuite.executable import executable, remote_executor


class TrexMode(Enum):
    STL = 0
    ASTF = 1
    STF = 2


PcapList = Sequence[Tuple[str, int | float]]


def send_to_remote(source: Path, hostname: str, destination: Path | None = None):
    if destination is None:
        destination = source

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
    executor = remote_executor.RemoteExecutor(host=hostname, user=os.environ["USER"])
    mkdir = executable.Tool(
        f"mkdir -p '{str(dir)}' && chmod 777 '{str(dir)}'",
        executor=executor,
        sudo=True,
    )
    mkdir.run()


def get_trex_mac(hostname: str, pci: str, trex_version: str):
    executor = remote_executor.RemoteExecutor(host=hostname, user=os.environ["USER"])
    get_mac = executable.Tool(
        f"cd /opt/trex/{trex_version} && ./dpdk_setup_ports.py -t | grep {pci[5:]} | awk '{{print $8}}'",
        executor=executor,
        sudo=True,
    )
    stdout, _ = get_mac.run()

    stdout = str(stdout).strip()
    assert len(stdout) == 17, f"Couldn't get MAC address for {pci}"
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
            return mode_enum
        else:
            pytest.skip(f"{forced_mode} is not supported by this test")

    preferred_mode = request.config.getoption("--prefer-trex-mode")
    if preferred_mode is not None:
        mode_enum = str_to_trex_mode(preferred_mode)
        if mode_enum is None:
            raise ValueError(f"{preferred_mode} is not a valid TRex mode")

        if mode_enum in available_modes:
            return mode_enum
        else:
            return available_modes[0]

    return available_modes[0]
