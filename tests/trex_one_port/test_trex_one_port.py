"""
Author(s): Adam Kiripolský <adamkiripolsky.official@gmail.com>

Copyright: (C) 2023 CESNET, z.s.p.o.

Suricata testing module.
"""

import pytest
import signal

from typing import List
from lbr_testsuite import trex
from add_vlan import edit_vlan
from util.suricata_manager import Suricata_manager, SuriDown
from util.suri_util import save_stats, TestInfo, RunInfo
from conftest import (
    kill_pytest,
    get_trex_multi,
    suri_interface_bind,
    Suri_conf,
    send_pcap_to_trex,
    return_filename,
)
from util.search_util import binary_search

TARGET_VLAN = 15  # claret
TARGET_MAC = "08:C0:EB:88:C5:38"


@pytest.mark.parametrize(
    "rules_config",
    [
        {"name": "norules", "path": "/dev/null/"},
        {"name": "rules", "path": "/var/lib/suricata/rules/suricata.rules"},
    ],
    ids=["norules", "rules"],
)
def test_trex_one_port(
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
    get_path_to_pcap: str,
    change_vlan_id: bool,
    rules_config: dict,
    b_search: bool,
    min_search_multiplier: float,
    max_search_multiplier: float,
    drop_rate: float,
    delta: float,
    max_cycles: int,
    repetitions: int,
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

    test_info.traffic_generator = True

    traffic_generator: trex.TRexStateless = trex_manager.request_stateless(request)
    traffic_generator.set_dst_mac(TARGET_MAC)
    traffic_generator.set_vlan(TARGET_VLAN)

    test_variant_name = f"{suri_conf.test_name}_{rules_config['name']}"
    trex_multipliers: List[float] = get_trex_multi(
        get_settings_file, suri_conf.server, suri_conf.pcie, test_variant_name
    )

    if change_vlan_id:
        pcap_filename = edit_vlan(get_path_to_pcap, TARGET_VLAN)
    else:
        pcap_filename = get_path_to_pcap
    send_pcap_to_trex(pcap_filename, request)

    tester = Test_run(
        traffic_generator, suri_daemon, pcap_filename, test_info, params, request
    )

    if b_search:
        max_multiplier = binary_search(
            tester.test_run,
            min_search_multiplier,
            max_search_multiplier,
            drop_rate,
            delta,
            max_cycles,
            repetitions,
        )
        print(
            f"\n[FINISH] Maximum multiplier found is: {max_multiplier:.4f}. | param_file={request.config.getoption('--param-file')} | params={params}\n\n"
        )
    else:
        for idx, multiplier in enumerate(trex_multipliers, 1):
            run_info = RunInfo(multiplier=multiplier)
            print(
                f"\n[Progress] multiplier {idx}/{len(trex_multipliers)} | param_file={request.config.getoption('--param-file')} | params={params}\n"
            )
            tester.run_test(run_info.multiplier)


class Test_run:
    def __init__(
        self, traffic_generator, suri_daemon, pcap_filename, test_info, params, request
    ):
        self.traffic_generator = traffic_generator
        self.suri_daemon = suri_daemon
        self.pcap_filename = pcap_filename
        self.test_info = test_info
        self.request = request
        self.params = params

    def test_run(self, multiplier: float, duration: int = None):
        print(f"\n[Progress] multiplier {multiplier}\n")

        self.traffic_generator.reset()
        try:
            self.suri_daemon.start()
        except SuriDown:
            pytest.fail("Suricata is down.")

        self.traffic_generator.get_handler().push_remote(
            pcap_filename=f"/tmp/pcaps/{return_filename(self.pcap_filename)}",
            ports=[0],
            ipg_usec=100,
            speedup=200 * multiplier,
            duration=self.test_info.traffic_duration,
        )

        self.traffic_generator.wait_on_traffic()

        try:
            self.suri_daemon.stop()
        except SuriDown:
            pytest.fail("Suricata was down.")

        run_info = RunInfo(multiplier)
        run_info.trex_server_stats = self.traffic_generator.get_stats()
        run_info.suricata_start_delay = self.suri_daemon.last_start_delay

        save_stats(self.params, self.request, self.test_info, run_info)
