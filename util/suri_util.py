#!/usr/bin/python

"""
Author(s): Adam Kiripolský <adamkiripolsky.official@gmail.com>

Copyright: (C) 2023 CESNET, z.s.p.o.
"""

from dataclasses import dataclass, field
import json
import jq
import time
import os.path

import matplotlib.pyplot as plt

from file_read_backwards import FileReadBackwards
from typing import List
from pathlib import Path
from shutil import copy as copy_content


@dataclass(frozen=True)
class TestInfo:
    result_path: str
    traffic_duration: int
    heatup_duration: int
    suricata_path_to_bin: str
    suricata_rules_paths: List[str]
    suricata_config_path: str
    comment: str = ""
    utilized_programs_info: dict = field(default_factory=dict)
    __test__: bool = False  # tell pytest that this class is not a test case


@dataclass
class RunInfo:
    multiplier: float = 0
    should_save_test_info: bool = True
    suricata_start_delay: int = 0
    trex_client_stats: dict | None = None
    trex_server_stats: dict | None = None
    trex_pretty_stats: dict = field(default_factory=dict)


def get_last_stats_line(file: str) -> str:
    with FileReadBackwards(file) as json_file:
        line: str = ""
        loaded_line: dict = {}

        while loaded_line.get("event_type", "") != "stats":
            line = json_file.readline()
            loaded_line = json.loads(line)

    return line


def put_last_stats_into_file(source_file: str, output_file: str):
    with open(output_file, "w") as new_file:
        new_file.write(get_last_stats_line(source_file))


def get_rx_packets_from_file(file: str, skip=0) -> int:
    json_loaded = json.loads(get_last_stats_line(file))
    pkts = jq.compile(".stats.decoder.pkts").input(json_loaded).first()

    try:
        return int(pkts) - get_rx_packets_until(file, skip)
    except ValueError:
        return 0


def get_rx_bytes_from_file(file: str, skip=0) -> int:
    json_loaded = json.loads(get_last_stats_line(file))
    bytes = jq.compile(".stats.decoder.bytes").input(json_loaded).first()

    try:
        return int(bytes) - get_rx_bytes_until(file, skip)
    except ValueError:
        return 0


def get_rx_packets_until(file: str, until: int) -> int:
    try:
        json_file = open(file, "r")
    except FileNotFoundError:
        return 0

    json_loaded = json_file.read()
    output = (
        jq.compile(
            f"select(.stats.uptime >= {until})"
            "| [.] | first"
            "| {total: .stats.decoder.pkts, missed: .stats.capture.dpdk.imissed}"
        )
        .input_text(json_loaded)
        .first()
    )

    try:
        return int(output["total"]) - int(output["missed"])
    except ValueError:
        return 0


def get_rx_bytes_until(file: str, until: int) -> int:
    try:
        json_file = open(file, "r")
    except FileNotFoundError:
        return 0

    json_loaded = json_file.read()
    output = (
        jq.compile(
            f"select(.stats.uptime >= {until})"
            "| [.] | first"
            "| {total: .stats.decoder.bytes, average: .stats.decoder.avg_pkt_size, missed: .stats.capture.dpdk.imissed}"
        )
        .input_text(json_loaded)
        .first()
    )

    try:
        return int(output["total"]) - int(output["missed"]) * int(output["average"])
    except ValueError:
        return 0


def get_total_packets_until(file: str, until: int) -> int:
    try:
        json_file = open(file, "r")
    except FileNotFoundError:
        return 0

    json_loaded = json_file.read()
    output = (
        jq.compile(
            f"select(.stats.uptime >= {until})| [.] | first| .stats.decoder.pkts"
        )
        .input_text(json_loaded)
        .first()
    )

    try:
        return int(output)
    except ValueError:
        return 0


def get_total_bytes_until(file: str, until: int) -> int:
    try:
        json_file = open(file, "r")
    except FileNotFoundError:
        return 0

    json_loaded = json_file.read()
    output = (
        jq.compile(
            f"select(.stats.uptime >= {until})| [.] | first| .stats.decoder.bytes"
        )
        .input_text(json_loaded)
        .first()
    )

    try:
        return int(output)
    except ValueError:
        return 0


def get_flow_filtered_packets_from_file(file: str, skip=0) -> int:
    json_loaded = json.loads(get_last_stats_line(file))
    flow_filtered = (
        jq.compile(".stats.capture.dpdk.rte_flow_filtered").input(json_loaded).first()
    )

    try:
        return int(flow_filtered) - get_flow_filtered_packets_until(file, skip)
    except (ValueError, TypeError):
        return 0


def get_flow_filtered_packets_until(file: str, until: int) -> int:
    try:
        json_file = open(file, "r")
    except FileNotFoundError:
        return 0

    json_loaded = json_file.read()
    output = (
        jq.compile(
            f"select(.stats.uptime >= {until})"
            "| [.] | first"
            "| .stats.capture.dpdk.rte_flow_filtered"
        )
        .input_text(json_loaded)
        .first()
    )

    try:
        return int(output)
    except (ValueError, TypeError):
        return 0


def get_stats_from_string(lines: str) -> str:
    result_line = ""
    split_lines = lines.split("/n")

    for i in range(len(split_lines) - 1, -1, -1):
        if "decoder" in split_lines[i]:
            result_line = split_lines[i]
            break

    json_loaded = json.loads(result_line)
    return jq.compile(".stats.decoder.pkts").input(json_loaded).first()


def is_running(stdout: str) -> bool:
    try:
        json_loaded = json.loads(stdout)
    except Exception:
        return False
    return jq.compile(".return").input(json_loaded).first() == "OK"


def convert_multiplier_to_str(multiplier: float) -> str:
    return (
        "unspecified_multiplier" if multiplier == 0 else f"multiplier_{str(multiplier)}"
    )


def save_stats(params, request, test_info: TestInfo, run_info: RunInfo):
    multiplier_str: str = convert_multiplier_to_str(run_info.multiplier)
    output_dir: str = os.path.join(test_info.result_path, multiplier_str)
    aggregated_output_path = os.path.join(test_info.result_path, "aggregated.json")

    os.makedirs(Path(output_dir), exist_ok=True)

    if run_info.should_save_test_info:
        save_test_info(request, test_info, aggregated_output_path)
        run_info.should_save_test_info = False

    save_suricata_stats(request, output_dir)
    save_trex_stats(run_info, output_dir)
    save_aggregated_stats(
        test_info, run_info, output_dir, aggregated_output_path, params
    )


def save_suricata_stats(request, output_dir: str):
    suricata_tmp_stats_path: str = (
        f"/tmp/suricata-{request.config.getoption('--user')}/"
    )

    if request.config.getoption("--collect-artifacts"):
        suricata_tmp_eve_path: str = os.path.join(suricata_tmp_stats_path, "eve.json")
        suricata_output_eve_path = os.path.join(output_dir, "eve.json")
        copy_content(suricata_tmp_eve_path, suricata_output_eve_path)

    suricata_tmp_eve_stats_path: str = os.path.join(
        suricata_tmp_stats_path, "eve-stats.json"
    )
    suricata_output_eve_stats_path = os.path.join(output_dir, "eve-stats.json")
    copy_content(suricata_tmp_eve_stats_path, suricata_output_eve_stats_path)


def save_trex_stats(run_info: RunInfo, output_dir: str):
    if run_info.trex_client_stats is not None:
        trex_client_output_path: str = os.path.join(output_dir, "trex_client.json")
        with open(trex_client_output_path, "w") as trex_client_stats_file:
            json.dump(run_info.trex_client_stats, trex_client_stats_file)

    if run_info.trex_server_stats is not None:
        trex_server_output_path: str = os.path.join(output_dir, "trex_server.json")
        with open(trex_server_output_path, "w") as trex_server_stats_file:
            json.dump(run_info.trex_server_stats, trex_server_stats_file)


def save_aggregated_stats(
    test_info: TestInfo,
    run_info: RunInfo,
    suri_stats_path: str,
    aggregated_output_path: str,
    params,
):
    out_params = params.copy()
    out_params.update(
        dpdk_version=test_info.utilized_programs_info.get("dpdk_version", "undefined")
    )
    eve_stats_path = os.path.join(suri_stats_path, "eve-stats.json")
    delay_time = test_info.heatup_duration + run_info.suricata_start_delay
    output: dict = {
        "event": "test_results",
        "trex_multiplier": run_info.multiplier,
        "transmit_seconds": test_info.traffic_duration,
        "suricata_rx_packets": get_rx_packets_from_file(
            eve_stats_path, skip=delay_time
        ),
        "suricata_rx_bytes": get_rx_bytes_from_file(eve_stats_path, skip=delay_time),
        "suricata_rte_flow_filtered_packets": get_flow_filtered_packets_from_file(
            eve_stats_path, skip=delay_time
        ),
        "trex_tx_packets": run_info.trex_pretty_stats["opackets"]
        - get_total_packets_until(
            eve_stats_path, test_info.heatup_duration + run_info.suricata_start_delay
        ),
        "trex_tx_bytes": run_info.trex_pretty_stats["obytes"]
        - get_total_bytes_until(
            eve_stats_path, test_info.heatup_duration + run_info.suricata_start_delay
        ),
        "parameters": out_params,
    }

    with open(aggregated_output_path, "a+") as output_file:
        json.dump(output, output_file)
        output_file.write("\n")


def save_test_info(request, test_info: TestInfo, aggregated_output_path: str) -> None:
    cmd_comment: str = request.config.getoption("--test-comment")
    output: dict = {
        "event": "test_info",
        "test_name": request.function.__name__,
        "suricata_binary_path": test_info.suricata_path_to_bin,
        "rules_file_paths": test_info.suricata_rules_paths,
        "config_path": test_info.suricata_config_path,
        "suricata_version": test_info.utilized_programs_info.get(
            "suricata_version", "undefined"
        ),
        "dpdk_version": test_info.utilized_programs_info.get(
            "dpdk_version", "undefined"
        ),
        "test_comment": cmd_comment if cmd_comment != "" else test_info.comment,
    }

    with open(aggregated_output_path, "a+") as output_file:
        json.dump(output, output_file)
        output_file.write("\n")


def print_stats(trex_stats: List[int], suri_stats: List[str]):
    print("\n")
    for i in range(len(trex_stats)):
        print("Trex tx: ", trex_stats[i], "Suri rx: ", suri_stats[i])


def make_graph(
    trx_multipliers: List[float], suri_stats: List[str], trx_stat: List[int]
):
    path_to_graph_directory: str = os.path.join(
        Path(__file__).parent, "results", "graphs"
    )
    time_format: str = "-".join(["%Y", "%m", "%d", "%H:%M"])
    path_to_graph: str = os.path.join(
        path_to_graph_directory, "suri_graph-" + time.strftime(time_format)
    )
    suri_rx: List[float] = [float(stat) for stat in suri_stats]
    trx_tx: List[float] = [float(stat) for stat in trx_stat]
    y_axis: List[float] = []

    os.makedirs(Path(path_to_graph_directory), exist_ok=True)
    for i in range(len(trx_tx)):
        y_axis.append(((trx_tx[i] - suri_rx[i]) / trx_tx[i]) * 100)

    plt.plot(trx_multipliers, y_axis)
    plt.xlabel("TRex cps multiplier")
    plt.ylabel("Suricata packets dropped in %")
    plt.title("Suricata performance test")
    plt.savefig(path_to_graph)
