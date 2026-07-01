"""
Author(s): Matyáš Sedmidubský <sedmidubsky@cesnet.cz>

Copyright: (C) 2026 CESNET, z.s.p.o.

Suricata testing module.
"""

import pytest
import signal

from typing import List
from lbr_testsuite import trex
from assets.trex.traffic_profiles.trex_client_manager import TrexMode
from assets.trex.traffic_profiles.web_50_sites_trex_profile import Web50SitesProfile
from util.suricata_manager import Suricata_manager, SuriDown
from util.suri_util import save_stats, TestInfo, RunInfo
from conftest import kill_pytest, get_trex_multi, suri_interface_bind, Suri_conf
from util.search_util import binary_search

@pytest.mark.parametrize(
    "rules_config",
    [
        {"name": "norules", "path": "/dev/null/"},
        {"name": "rules", "path": "/var/lib/suricata/rules/suricata.rules"},
    ],
    ids=["norules", "rules"],
)

def test_web_50_sites(
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
    b_search: bool,
    min_search_multiplier: float,
    max_search_multiplier: float,
    drop_rate: float,
    delta: float,
    max_cycles: int,
    repetitions: int
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

    trex_client = Web50SitesProfile(
        trex_manager, request, get_target_mac, get_target_vlan, mode=TrexMode.STF
    )

    test_variant_name = f"{suri_conf.test_name}_{rules_config['name']}"
    trex_multipliers: List[float] = get_trex_multi(
        get_settings_file, suri_conf.server, suri_conf.pcie, test_variant_name
    )

    tester = Test_run(trex_client, suri_daemon, test_info, params, request)

    if b_search:
        max_multiplier = binary_search(tester.test_run, min_search_multiplier,
                max_search_multiplier, drop_rate, delta, max_cycles, repetitions)
        print(f"\n[FINISH] Maximum multiplier found is: {max_multiplier:.4f}. | param_file={request.config.getoption('--param-file')} | params={params}\n\n")
    else:
        for idx, multiplier in enumerate(trex_multipliers, 1):
            print(
                f"\n[Progress] multiplier {idx}/{len(trex_multipliers)} | param_file={request.config.getoption('--param-file')} | params={params}"
            )
            print(f"sending packets at {multiplier} * default cps of .pcap")
            tester.test_run(multiplier)

class Test_run:
    __test__ = False
    def __init__(self, client, suri_daemon, test_info, params, request):
        self.trex_client = client
        self.suri_daemon = suri_daemon
        self.test_info = test_info
        self.params = params
        self.request = request

    def test_run(self, multiplier: float, duration: int = None):
        if duration is None:
            duration = self.test_info.traffic_duration

        self.trex_client.set_props(multiplier, duration)
        self.trex_client.prepare()

        try:
            self.suri_daemon.start()
        except SuriDown:
            pytest.fail("Suricata is down.")

        self.trex_client.run()

        try:
            self.suri_daemon.stop()
        except SuriDown:
            pytest.fail("Suricata was down.")

        run_info = RunInfo(multiplier=multiplier)
        self.trex_client.update_runinfo(run_info)
        run_info.suricata_start_delay = self.suri_daemon.last_start_delay

        save_stats(self.params, self.request, self.test_info, run_info)
