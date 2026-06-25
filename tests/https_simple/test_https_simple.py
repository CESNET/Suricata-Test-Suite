"""
Author(s): Adam Kiripolský <adamkiripolsky.official@gmail.com>

Copyright: (C) 2023 CESNET, z.s.p.o.

Suricata testing module.

Usage:
    Without topology:
        pytest --trex-generator="trex,0000:65:00.0" --remote-host="claret,0000:3b:00.0" -s --log-level=info
"""


import pytest
import os
import signal

from pathlib import Path
from typing import List
from lbr_testsuite import trex
from util.suricata_manager import Suricata_manager, SuriDown
from util.suri_util import save_stats, TestInfo, RunInfo
from assets.trex.traffic_profiles import https_trex_profile
from functools import partial
from conftest import kill_pytest, get_trex_multi, suri_interface_bind, Suri_conf
from util.search_util import binary_search

TARGET_VLAN = 15 # claret
TARGET_MAC = "08:C0:EB:88:C5:38"

@pytest.mark.parametrize("rules_config", [
    {"name": "norules", "path": "/dev/null/"},
    {"name": "rules", "path": "/var/lib/suricata/rules/suricata.rules"}
], ids=["norules", "rules"])

def test_https_simple (
    request: pytest.FixtureRequest,
    trex_generators: dict,
    result_path: str,
    suricata_tmp_stats_path: str,
    utilized_programs_info: dict,
    params: dict,
    suri_conf: Suri_conf,
    get_settings_file : str,
    get_traffic_duration : int,
    get_heatup_duration: int,
    rules_config: dict,
    b_search: bool,
    min_search_multiplier: float,
    max_search_multiplier: float,
    drop_rate: float,
    delta: float,
    max_cycles: int,
    repetitions: int
    ):

    trex_manager: trex.TRexManager = trex.TRexManager(trex.TRexMachinesPool(trex_generators))

    suri_daemon: Suricata_manager = Suricata_manager(request,
                                                     suricata_tmp_stats_path,
                                                     interface=suri_interface_bind(request)[0],
                                                     capture_mode=suri_interface_bind(request)[1],
                                                     conf_file=suri_conf.conf_file.with_params(params).build(),
                                                     rules_file=rules_config["path"],
                                                     )
    signal.signal(signal.SIGINT, kill_pytest)

    test_info = TestInfo(result_path=result_path,
                         traffic_duration=get_traffic_duration,
                         heatup_duration=get_heatup_duration,
                         suricata_path_to_bin=suri_daemon.get_path_to_binary(),
                         suricata_rules_paths=[suri_daemon.rules_file],
                         suricata_config_path=suri_daemon.conf_file,
                         utilized_programs_info=utilized_programs_info
                         )

    trex_client: trex.TRexAdvancedStateful = trex_manager.request_stateful(request, role="client")

    trex_server : trex.TRexAdvancedStateful = trex_manager.request_stateful(request, role="server")

    trex_client.set_dst_mac(trex_server.get_src_mac())
    trex_client.set_vlan(TARGET_VLAN)

    trex_server.set_dst_mac(trex_client.get_src_mac())
    trex_server.set_vlan(TARGET_VLAN)

    test_variant_name = f"{suri_conf.test_name}_{rules_config['name']}"
    trex_multipliers: List[float] = get_trex_multi(get_settings_file, suri_conf.server, suri_conf.pcie, test_variant_name)


    tester = Test_run(trex_server, trex_client, suri_daemon, test_info, params, request)

    if b_search:
        max_multiplier = binary_search(tester.test_run, min_search_multiplier,
                max_search_multiplier, drop_rate, delta, max_cycles, repetitions)
        print(f"\n[FINISH] Maximum multiplier found is: {max_multiplier:.4f}. | param_file={request.config.getoption('--param-file')} | params={params}\n\n")

    else:
        for idx, multiplier in enumerate(trex_multipliers, 1):
            run_info = RunInfo(multiplier=multiplier)
            print(f"\n[Progress] multiplier {idx}/{len(trex_multipliers)} | param_file={request.config.getoption('--param-file')} | params={params}")
            print(f"sending packets at {run_info.multiplier} * default cps of .pcap")
            tester.test_run(run_info.multiplier)

class Test_run:
    def __init__(self, server, client, suri_daemon, test_info, params, request):
        self.trex_server = server
        self.trex_client = client
        self.suri_daemon = suri_daemon
        self.test_info = test_info
        self.params = params
        self.request = request

    def test_run(self, multiplier: float, duration: int = None):
        if duration is None:
            duration = self.test_info.traffic_duration

        self.trex_server.reset()
        self.trex_client.reset()

        trex_profile: trex.TRexProfilePcap = https_trex_profile.create_profile(multiplier)

        self.trex_server.load_profile(trex_profile)
        self.trex_client.load_profile(trex_profile)

        try:
            self.suri_daemon.start()
        except SuriDown:
            pytest.fail("Suricata is down.")
        time.sleep(5)

        self.trex_server.start()
        self.trex_client.start(duration=duration)

        self.trex_client.wait_on_traffic()
        self.trex_server.stop()

        try:
            self.suri_daemon.stop()
        except SuriDown:
            pytest.fail("Suricata was down.")

        run_info = RunInfo(multiplier=multiplier)
        run_info.trex_client_stats = self.trex_client.get_stats()
        run_info.trex_server_stats = self.trex_server.get_stats()
        run_info.suricata_start_delay = self.suri_daemon.last_start_delay

        save_stats(self.params, self.request, self.test_info, run_info)
