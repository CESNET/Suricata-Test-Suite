"""
Author(s): Adam Kiripolský <adamkiripolsky.official@gmail.com>

Copyright: (C) 2023 CESNET, z.s.p.o.
"""

import sys
import pytest
import os.path
import time
import importlib.util
from os import access, R_OK
from os.path import isfile
import json
import jq
import re

from dataclasses import dataclass
from lbr_testsuite.executable import executable, remote_executor
from lbr_trex_client.interactive import trex
from typing import Tuple, List
from pathlib import Path
from itertools import product
from param import filter
from util.config_builder import ConfigBuilder

TIME_STR = time.strftime("-".join(["%Y", "%m", "%d", "%H:%M"]))
PATH_TO_ARTEFACTS: str = str(Path(__file__).parent / "results" / "artefacts")

# alias lbr_trex_client.interactive.trex to trex for importing native TRex profiles
sys.modules["trex"] = trex


def pytest_addoption(parser):
    parser.addoption(
        "--remote-host",
        type=str,
        default=None,
        action="store",
        help=(
            "Specify one remote host. "
            "Remote is represented by hostname "
            "Examples: \n"
            "    --remote-host='claret'\n"
        ),
    )
    parser.addoption(
        "--user",
        type=str,
        default=None,
        action="store",
        help=("Specify user that operates on the machine. "),
    )
    parser.addoption(
        "--suricata-hugepages",
        type=str,
        default="4G",
        action="store",
        help=("Specify amount of hugepages to be setup on remote machine. "),
    )
    parser.addoption(
        "--suricata-cfg",
        type=str,
        default="",
        action="store",
        help=("Specify path to default configuration to be used with Suricata. "),
    )
    parser.addoption(
        "--collect-artifacts",
        default=False,
        action="store_true",
        help=("Turn on collecting artifact data from individual tests. "),
    )
    parser.addoption(
        "--test-comment",
        type=str,
        default="",
        action="store",
        help=("Set test-wide comment containg information about current test-run. "),
    )
    parser.addoption(
        "--param-file",
        type=str,
        default="",
        action="store",
        help=("Specify name of file with parameters"),
    )
    parser.addoption(
        "--traffic-duration",
        type=int,
        default=300,
        action="store",
        help=("Change test duration."),
    )
    parser.addoption(
        "--heatup-duration",
        type=int,
        default=0,
        action="store",
        help=("Specify for how long to wait before measuring statistics"),
    )
    parser.addoption(
        "--pcap-replay",
        type=str,
        default=str(
            Path(__file__).parent
            / "assets"
            / "trex"
            / "traffic_profiles"
            / "pcaps"
            / "upf_dns.pcap"
        ),
        action="store",
        help=("Pcap file to replay in pcap_replay."),
    )
    parser.addoption(
        "--target-mac",
        type=str,
        default="",
        action="store",
        help=("Mac address to send traffic to when not using ASTF TRex."),
    )
    parser.addoption(
        "--target-vlan",
        type=int,
        default=0,
        action="store",
        help=("Generate traffic with this VLAN ID. 0 (default) for untagged."),
    )

    parser.addoption(
        "--binary-search",
        default=False,
        action="store_true",
        help=(
            "Use binary search mode for finding optimal Suricata speed."
        )
    )

    parser.addoption(
        "--min-search-multiplier",
        default=0.0,
        type=float,
        action="store",
        help=(
            "Minimum multiplier to find value from."
        )
    )

    parser.addoption(
        "--max-search-multiplier",
        default=10.0,
        type=float,
        action="store",
        help=(
            "Maximum multiplier to find value up to."
        )
    )

    parser.addoption(
        "--drop-rate",
        type=float,
        default=1.0,
        action="store",
        help=(
            "Target drop rate in percentage."
        )
    )

    parser.addoption(
        "--delta", type=float, default=0.05, action="store", help=("Minimum delta between cycles.")
    )

    parser.addoption(
        "--max-cycles",
        type=int,
        default=20,
        action="store",
        help=(
            "Maximum amount of steps for binary search."
        )
    )

    parser.addoption(
        "--repetitions",
        type=int,
        default=2,
        action="store",
        help=(
            "Maximum amount of repetitions per multiplier."
        )
    )

def get_suri_executor(request) -> remote_executor.Executor:
    host_name = get_host_internal(request)
    user = get_user_internal(request)

    return remote_executor.RemoteExecutor(host=host_name, user=user)


def get_trex_executor(request):
    trex_name = get_trex_internal(request)
    user = get_user_internal(request)

    return remote_executor.RemoteExecutor(host=trex_name, user=user)


def get_host_internal(request) -> Tuple[str, str]:
    return request.config.getoption("--remote-host")


def get_user_internal(request) -> str:
    return request.config.getoption("--user")


def get_trex_internal(request):
    trex_gen = request.config.getoption("--trex-generator")
    return trex_gen[0].split(",")[0]


def pytest_generate_tests(metafunc):
    if "params" in metafunc.fixturenames:
        params = []
        capture_modes_in_run = get_capture_modes_in_run(
            metafunc.config.getoption("--param-file")
        )
        capture_modes = get_capture_modes(metafunc.config.getoption("--param-file"))

        for suricata_capture_mode in capture_modes_in_run:
            filter_suricata_capture_modes = [
                mode for mode in capture_modes if mode != suricata_capture_mode
            ]

            raw_runs = parametrize_args(metafunc.config.getoption("--param-file"))
            if raw_runs:
                for run in raw_runs:
                    run = {
                        k: v
                        for k, v in run.items()
                        if not any(mode in k for mode in filter_suricata_capture_modes)
                    }  # unwanted capture modes
                    if run:
                        params.append(run)
                        af_packet_get_queues_rx_descriptors(
                            metafunc.config.getoption("--param-file"), params
                        )

            assert params, "empty parameters, unable to set interface"

        params = [
            dict(t) for t in {tuple(d.items()) for d in params}
        ]  # remove duplicate
        params = filters_apply(params)
        metafunc.parametrize("params", params)


def kill_pytest(sigum, frame):
    pytest.exit("Ctl+C was pressed")


@pytest.fixture()
def get_traffic_duration(request):
    return request.config.getoption("--traffic-duration")


@pytest.fixture()
def get_heatup_duration(request):
    return request.config.getoption("--heatup-duration")


@pytest.fixture()
def get_path_to_pcap(request):
    return request.config.getoption("--pcap-replay")


@pytest.fixture()
def get_target_mac(request):
    return request.config.getoption("--target-mac")


@pytest.fixture()
def get_target_vlan(request):
    return request.config.getoption("--target-vlan")

@pytest.fixture()
def b_search(request):
    return request.config.getoption("--binary-search")

@pytest.fixture()
def min_search_multiplier(request):
    return float(request.config.getoption("--min-search-multiplier"))

@pytest.fixture()
def max_search_multiplier(request):
    return float(request.config.getoption("--max-search-multiplier"))

@pytest.fixture()
def drop_rate(request):
    return float(request.config.getoption("--drop-rate"))

@pytest.fixture()
def delta(request):
    return float(request.config.getoption("--delta"))

@pytest.fixture()
def max_cycles(request):
    return int(request.config.getoption("--max-cycles"))

@pytest.fixture()
def repetitions(request):
    return int(request.config.getoption("--repetitions"))

def return_filename(pcap_filename):
    match = re.search(r"[^\/]+\.pcap$", pcap_filename)
    assert match, "file is incorrectly specified"
    return match.group(0)


def send_pcap_to_trex(pcap_filename, request):

    pcaps_dir_trex = executable.Tool(
        "mkdir -p /tmp/pcaps/ && chmod 777 /tmp/pcaps/",
        executor=get_trex_executor(request),
        sudo=True,
    )
    pcaps_dir_trex.run()

    os.system(
        f"rsync -z --checksum --update {pcap_filename} $(whoami)@{get_trex_internal(request)}.liberouter.org:/tmp/pcaps"
    )


@pytest.fixture(scope="function")
def get_test_name(request):
    """Function, that returns a name of a current test"""
    return request.node.name.split("[")[0]


def suri_interface_bind(request):
    for parameter_path in request.node.callspec.params["params"].keys():
        dpdk_match = re.match(r"dpdk.interfaces\[[0-9]+\].interface", parameter_path)
        af_packet_match = re.match(r"af-packet\[[0-9]+\].interface", parameter_path)

        if dpdk_match is not None:
            return (request.node.callspec.params["params"][parameter_path], "dpdk")
        elif af_packet_match is not None:
            return (request.node.callspec.params["params"][parameter_path], "af-packet")

    assert dpdk_match is not None or af_packet_match is not None


@pytest.fixture(autouse=True)
def bind(request):
    pcies_to_vfio = ["X710", "E810-C"]
    binds_info = executable.Tool(
        f"dpdk-devbind -s | grep {suri_interface_bind(request)[0]}",
        sudo=True,
        executor=get_suri_executor(request),
    )
    pcie_info = str(binds_info.run())
    for pcie in pcies_to_vfio:
        if pcie in pcie_info:
            pcie_bind = executable.Tool(
                f"modprobe vfio-pci; echo 1 | sudo tee /sys/module/vfio/parameters/enable_unsafe_noiommu_mode; dpdk-devbind.py -b vfio-pci {suri_interface_bind(request)[0]}",
                sudo=True,
                executor=get_suri_executor(request),
            )
            pcie_bind.run()


@pytest.fixture(scope="function")
def suricata_conf_file(request) -> ConfigBuilder:
    destination_dir = Path(request.node.path).parent / "tmp"
    editable_yaml = str(destination_dir / "suricata.yaml")

    os.makedirs(str(destination_dir), exist_ok=True)

    if request.config.getoption("--suricata-cfg"):
        builder = ConfigBuilder(
            editable_yaml, request.config.getoption("--suricata-cfg")
        )
    else:
        builder = ConfigBuilder(editable_yaml)

    return builder


@pytest.fixture(scope="function")
def result_path(request):
    return os.path.join(PATH_TO_ARTEFACTS, TIME_STR, request.function.__name__)


@pytest.fixture(scope="session", autouse=True)
def suricata_tmp_stats_path():
    return "/tmp"


@pytest.fixture(scope="function")
def utilized_programs_info(request):
    get_dpdk_version_process = executable.Tool(
        "pkg-config --modversion libdpdk", executor=get_suri_executor(request)
    )
    dpdk_version, _ = get_dpdk_version_process.run()

    get_suricata_version_process = executable.Tool(
        "suricata --build-info | head -1", executor=get_suri_executor(request)
    )
    suricata_version, _ = get_suricata_version_process.run()
    return {
        "dpdk_version": dpdk_version.strip(),
        "suricata_version": " ".join(suricata_version.split()[4:]),
    }


@pytest.fixture(autouse=True)
def assert_available_machines(request) -> None:
    host_pcie_adress = suri_interface_bind(request)[0]

    process_get_pcie_match = executable.Tool(
        f"lshw -c network | grep -c {host_pcie_adress} > /tmp/pcie_count",
        sudo=True,
        executor=get_suri_executor(request),
    )
    process_get_pcie_match.run()

    print_pcie_match = executable.Tool(
        "cat /tmp/pcie_count",
        sudo=True,
        executor=get_suri_executor(request),
    )
    stdout, stderr = print_pcie_match.run()

    assert stderr == "", (
        f"Error while gathering information about pcie interfaces, stderr: {stderr}"
    )
    assert int(stdout) > 0, "Interface on host not found"


def hugepages_allocated(request) -> bool:
    process_cat_hugepages_count = executable.Tool(
        "cat /proc/meminfo | grep 'HugePages_Free:' > /tmp/hugepages_allocated_info",
        executor=get_suri_executor(request),
        sudo=True,
    )
    process_cat_hugepages_count.run()

    process_get_hugepages_count_str = executable.Tool(
        "cat /tmp/hugepages_allocated_info",
        sudo=True,
        executor=get_suri_executor(request),
    )
    stdout, stderr = process_get_hugepages_count_str.run()

    assert stderr == "", (
        f"Error while gathering information about allocated hugepages: {stderr}"
    )

    # huge_pages[0] == "HugePages_Free:", huge_pages[1] is some nubmer as `str`
    huge_pages: List[str] = stdout.split()

    return huge_pages[1] != "0"


@pytest.fixture(scope="session", autouse=True)
def check_hugepages(request) -> None:
    if hugepages_allocated(request):
        print("Huge-pages already allocated")
        return

    print("Allocating huge-pages")
    process_set_hugepages = executable.Tool(
        f"dpdk-hugepages.py --setup {request.config.getoption('--suricata-hugepages')}",
        sudo=True,
        executor=get_suri_executor(request),
    )

    _, stderr = process_set_hugepages.run()

    assert stderr == "", f"Error while allocating hugepages: {stderr}"


def file_is_accessible(file):
    assert isfile(file) and access(file, R_OK), (
        f"File {file} doesn't exist or isn't readable"
    )


def import_module(param_file):
    module_name_of_param_file = param_file.split(".")[0]
    module_path = os.path.join(Path(__file__).parent, param_file)
    spec = importlib.util.spec_from_file_location(
        module_name_of_param_file, module_path
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parametrize_args(param_file):
    file_is_accessible(param_file)
    module = import_module(param_file)
    if hasattr(module, "suri_yaml_params"):
        parametrize_args = [
            dict(zip(module.suri_yaml_params.keys(), combination))
            for combination in product(*module.suri_yaml_params.values())
        ]
        return parametrize_args
    return


def get_trex_multi(test_settings_file, server, pci, test_name):
    file_is_accessible(test_settings_file)
    with open(test_settings_file) as f:
        data = json.load(f)
        query_result = (
            str(
                jq.compile(
                    f'.configuration.tests[] | select(.test_name == "{test_name}") | .servers[] | select(.server_name == "{server}") | .pci[] | select(.pcie_addr == "{pci}") | .trex_multipliers'
                )
                .input_value(data)
                .all()
            )
            .replace("[", "")
            .replace("]", "")
        )
        try:
            multipliers = [float(i) for i in query_result.split(",")]
        except ValueError:
            raise ValueError(
                f"No match found for {server} and {pci} in {test_settings_file}:{test_name}"
            )
        return multipliers


def filters_apply(parametrize_args):
    filtered_combs = []

    for parameter_comb in parametrize_args:
        for parameter in parameter_comb.keys():
            dpdk_match = re.match(r"dpdk.interfaces\[[0-9]+\].interface", parameter)
            af_packet_match = re.match(r"af-packet\[[0-9]+\].interface", parameter)

            if dpdk_match is not None:
                new_filter = filter.get("dpdk", [])
                if all(f(parameter_comb) for f in new_filter):
                    filtered_combs.append(parameter_comb)
                break

            elif af_packet_match is not None:
                new_filter = filter.get("af-packet", [])
                if all(f(parameter_comb) for f in new_filter):
                    filtered_combs.append(parameter_comb)
                break

    return filtered_combs


@pytest.fixture(autouse=True)
def suri_conf(request, suricata_conf_file, get_test_name):
    return Suri_conf(
        conf_file=suricata_conf_file,
        server=get_host_internal(request),
        pcie=suri_interface_bind(request)[0],
        test_name=get_test_name,
    )


@dataclass
class Suri_conf:
    conf_file: ConfigBuilder
    server: str
    pcie: str
    test_name: str


@pytest.fixture()
def get_settings_file(request):
    return str(request.node.path.parent / "test_settings.json")


def get_capture_modes_in_run(param_file):
    file_is_accessible(param_file)
    module = import_module(param_file)
    if hasattr(module, "suri_cmd_params"):
        return module.suri_cmd_params["capture-mode"]

    return ["dpdk"]  # default mode


def get_capture_modes(param_file):
    file_is_accessible(param_file)
    module = import_module(param_file)
    if hasattr(module, "capture_modes"):
        return module.capture_modes


def make_combinations_for_af_packet(queues, rx_descriptors):
    combinations = [
        [i, j] for i in queues for j in rx_descriptors
    ]  # first thread, second rx_descriptors
    return combinations


@pytest.fixture()
def determine_capture_mode(request, get_settings_file):
    print(f"capture mode: {suri_interface_bind(request)[1]}")


@pytest.fixture(autouse=True)
def setup_af_packet(request):
    current_parameters = request.node.callspec.params["params"]
    if (
        "queues" in current_parameters.keys()
        and "rx_descriptors" in current_parameters.keys()
    ):
        interface = suri_interface_bind(request)[0]
        workers = current_parameters["queues"]
        af_setup_prompts = [
            f"ip link set {interface} down",
            f"/usr/sbin/ethtool -L {interface} combined {workers}",
            f"/usr/sbin/ethtool -K {interface} rxhash on",
            f"/usr/sbin/ethtool -K {interface} ntuple on",
            f"ip link set {interface} up",
            f"/usr/sbin/ethtool -X {interface} hkey 6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A:6D:5A equal {workers}",
            f"/usr/sbin/ethtool -A {interface} rx off",
            f"/usr/sbin/ethtool -C {interface} adaptive-rx off adaptive-tx off rx-usecs 1",
            f"/usr/sbin/ethtool -G {interface} rx {current_parameters['rx_descriptors']}",
            f"/usr/sbin/ethtool -X {interface} hfunc toeplitz",
        ]

        for af_setup_prompt in af_setup_prompts:
            set_af_packet = executable.Tool(
                f"{af_setup_prompt}",
                sudo=True,
                executor=get_suri_executor(request),
            )
            set_af_packet.run()


def af_packet_get_queues_rx_descriptors(param_file, params):

    for parameter_path in params[-1].keys():
        af_packet_match = re.match(r"af-packet\[[0-9]+\].interface", parameter_path)

        if af_packet_match is not None:
            key = af_packet_match.group(0)
            parameters = params[-1]
        else:
            return

    queues_not_empty = False
    rx_descriptors_not_empty = False

    file_is_accessible(param_file)
    module = import_module(param_file)
    if hasattr(module, "afp_ethtool"):
        query_result = (
            str(
                jq.compile(
                    f'.ifaces[] | select(.pcie_addr == "{parameters[key]}") | .queues[]'
                )
                .input_value(module.afp_ethtool)
                .all()
            )
            .replace("[", "")
            .replace("]", "")
        )
        if query_result:  # empty str
            queues = [int(i) for i in query_result.split(",")]
            queues_not_empty = True

        query_result = (
            str(
                jq.compile(
                    f'.ifaces[] | select(.pcie_addr == "{parameters[key]}") | .rx_descriptors[]'
                )
                .input_value(module.afp_ethtool)
                .all()
            )
            .replace("[", "")
            .replace("]", "")
        )
        if query_result:  # empty str
            rx_descriptors = [int(i) for i in query_result.split(",")]
            rx_descriptors_not_empty = True

        assert (
            queues_not_empty and rx_descriptors_not_empty
        )  # cannot be empty because of settings

        combinations = make_combinations_for_af_packet(queues, rx_descriptors)
        params.pop()
        for combination in combinations:
            new_parameters = parameters.copy()
            new_parameters["queues"] = combination[0]
            new_parameters["rx_descriptors"] = combination[1]
            params.append(new_parameters)
        return
