"""
Author(s):  Eliška Červinková <eliska.cervinkova@cesnet.cz>
            Adam Kiripolský <adam.kiripolsky@cesnet.cz>
            Matyáš Sedmidubský <matyas.sedmidubsky@cesnet.cz>
            Dávid Hanko <david.hanko@cesnet.cz>

Copyright: (C) 2023 - 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

Suricata testing module.
"""

import pytest
import signal

from typing import List
from lbr_testsuite import trex
from util.suricata_manager import Suricata_manager
from util.suri_util import TestInfo, get_drop_rate
from assets.trex.traffic_profiles.http_https_smb_trex_profile.profile import (
    HttpHttpsSmbProfile,
)
from conftest import kill_pytest, get_trex_multi, suri_interface_bind, Suri_conf
from util.trex_util import TrexMode, get_trex_mode
from util.multiplier_iterator import multiplier_iterator_create
from util.test_runner import TrexTestRun


@pytest.mark.parametrize(
    "rules_config",
    [
        {"name": "norules", "path": "/dev/null/"},
        {"name": "rules", "path": "/var/lib/suricata/rules/suricata.rules"},
    ],
    ids=["norules", "rules"],
)
def test_http_https_smb(
    request: pytest.FixtureRequest,
    trex_generators: dict,
    result_path: str,
    suricata_tmp_stats_path: str,
    utilized_programs_info: dict,
    params: dict,
    suri_conf: Suri_conf,
    get_settings_file: str,
    get_traffic_duration: int,
    get_heatup_duration: int,
    rules_config: dict,
    get_target_mac: str,
    get_target_vlan: int,
    b_search: dict | None,
):
    trex_manager: trex.TRexManager = trex.TRexManager(
        trex.TRexMachinesPool(trex_generators)
    )

    suri_daemon: Suricata_manager = Suricata_manager(
        request,
        suricata_tmp_stats_path,
        interface=suri_interface_bind(request)[0],
        capture_mode=suri_interface_bind(request)[1],
        conf_file=suri_conf.conf_file.with_params(params).build(),
        rules_file=rules_config["path"],
    )
    signal.signal(signal.SIGINT, kill_pytest)

    test_info = TestInfo(
        result_path=result_path,
        traffic_duration=get_traffic_duration,
        heatup_duration=get_heatup_duration,
        suricata_path_to_bin=suri_daemon.get_path_to_binary(),
        suricata_rules_paths=[suri_daemon.rules_file],
        suricata_config_path=suri_daemon.conf_file,
        utilized_programs_info=utilized_programs_info,
    )

    trex_mode = get_trex_mode(request, [TrexMode.ASTF, TrexMode.STF])
    trex_client = HttpHttpsSmbProfile(
        trex_manager, request, get_target_mac, get_target_vlan, mode=trex_mode
    )

    test_variant_name = f"{suri_conf.test_name}_{rules_config['name']}"
    trex_multipliers: List[float] = get_trex_multi(
        get_settings_file, suri_conf.server, suri_conf.pcie, test_variant_name
    )

    tester = TrexTestRun(trex_client, suri_daemon, test_info, params, request)

    mult_iter = multiplier_iterator_create(b_search, trex_multipliers)
    for multiplier in mult_iter:
        print(
            f"\n[Progress] multiplier {multiplier:.4f} | param_file={request.config.getoption('--param-file')} | params={params}"
        )
        tester.execute(multiplier)
        mult_iter.set_result(get_drop_rate())

    if mult_iter.result is not None:
        print(
            f"\n[FINISH] Maximum multiplier found is: {mult_iter.result:.4f}. | param_file={request.config.getoption('--param-file')} | params={params}\n\n"
        )
    else:
        print(
            f"\n[FINISH] Enumeration complete. | param_file={request.config.getoption('--param-file')} | params={params}\n\n"
        )
