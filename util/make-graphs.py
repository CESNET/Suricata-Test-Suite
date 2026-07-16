#!/usr/bin/python3
"""
Author(s):  Eliška Červinková <eliska.cervinkova@cesnet.cz>
            Adam Kiripolský <adam.kiripolsky@cesnet.cz>

Copyright: (C) 2023 - 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause
"""

import sys
import json
import os
import argparse
import matplotlib.pyplot as plt

from dataclasses import dataclass
from pathlib import Path
from typing import List, Tuple

Graph_function_params = Tuple[List[float], List[float], str]


@dataclass
class GraphLine:
    x_axis: List[float]
    y_axis: List[float]
    line_name: str
    parameters: dict


@dataclass
class ResultsRow:
    tx_time: float = 0.0
    tx_bytes: int = 0
    tx_packets: int = 0
    rx_bytes: int = 0
    rx_packets: int = 0


def parse_row(data: dict) -> ResultsRow:
    return ResultsRow(
        tx_time=float(data["transmit_seconds"]),
        tx_bytes=int(data["trex_tx_bytes"]),
        tx_packets=int(data["trex_tx_packets"]),
        rx_bytes=int(data["suricata_rx_bytes"]),
        rx_packets=int(data["suricata_rx_packets"]),
    )


def process_results_line(x_axis: List[float], y_axis: List[float], stats: dict):
    r_row: ResultsRow = parse_row(stats)

    x_axis.append(r_row.tx_bytes * 8 / (r_row.tx_time * 10**6))
    print(x_axis)

    print(f"Received packets total: {r_row.rx_packets}")
    print(f"Transmitted packets total: {r_row.tx_packets}")

    dropped_pkts: int = r_row.tx_packets - r_row.rx_packets
    print(f"Dropped packets total: {dropped_pkts}")
    y_axis.append(100 * dropped_pkts / r_row.tx_packets if r_row.tx_packets != 0 else 0)
    print(y_axis)


def process_info_line(info: dict, file_names: List[str], first_in_json) -> str:
    graph_name: str = info.get("test_name", "")
    run_comment = info.get("test_run_comment", "")
    if first_in_json:
        file_names.append(graph_name)
    if run_comment != "":
        graph_name += f" - {run_comment}"
    return graph_name


def get_min_first_x_axis(graph_lines: List[GraphLine]) -> float:
    """
    Args:
        graph_lines (List[GraphLine]):
            List of datasets containing information about test runs of suricata
    Returns:
        int: Minimal value from x_axis lists on index 0 to set correctly left limit on plotted graph

    """
    min: float = graph_lines[0].x_axis[0]
    for graph_line in graph_lines:
        if graph_line.x_axis[0] < min:
            min = graph_line.x_axis[0]
    return min


def make_graph(graph_lines: List[GraphLine], file_names: List[str]):
    output_dir: Path = Path(__file__).parent.parent / "results" / "graphs"
    os.makedirs(output_dir, exist_ok=True)
    x_label: str = "Transmit speed [Mbps]"
    y_label: str = "Dropped packets (%)"

    print(graph_lines)
    plt.rcParams.update({"font.size": 7.5})
    for graph_line in graph_lines:
        plt.plot(
            graph_line.x_axis,
            graph_line.y_axis,
            label=graph_line.line_name + " " + str(graph_line.parameters),
        )

    plt.xlim(left=(get_min_first_x_axis(graph_lines) // 1000) * 1000)
    plt.xlabel(x_label)
    plt.ylabel(y_label)
    plt.legend()
    plt.subplots_adjust(left=0.16, right=0.99, top=0.90, bottom=0.15)
    plt.grid(visible=True)
    plt.margins(x=0.01, y=0.01)
    plt.show()
    plt.savefig(str(output_dir / "-".join(file_names)))


def main(*args):
    graph_lines: List[GraphLine] = []
    file_names: List[str] = []

    for arg in args:
        with open(arg, "r") as json_file:
            x_axis: List[float] = []
            y_axis: List[float] = []
            graph_title: str = ""
            parameters: dict = {}
            first_check = True
            print(f"Input file: {arg}")

            for line in json_file:
                agg_dict: dict = json.loads(line)
                if agg_dict.get("event", "") == "test_results":
                    parameters = {
                        key.split(".")[-1]: value
                        for (key, value) in agg_dict.get("parameters").items()
                    }
                    process_results_line(x_axis, y_axis, agg_dict)
                if agg_dict.get("event", "") == "test_info":
                    graph_title = process_info_line(agg_dict, file_names, first_check)
                    if not first_check:
                        graph_lines.append(
                            GraphLine(x_axis, y_axis, graph_title, parameters)
                        )
                        x_axis = []
                        y_axis = []
                    first_check = False
            graph_lines.append(GraphLine(x_axis, y_axis, graph_title, parameters))

    make_graph(graph_lines, file_names)


if __name__ == "__main__":
    if len(sys.argv) < 1:
        raise SyntaxError("Insufficient arguments.")

    parser = argparse.ArgumentParser(
        usage="%(prog)s [path to aggregated1.json] [path to aggregated2.json] ..."
    )
    parser.add_argument(nargs="+", dest="paths to files")
    args = parser.parse_args()

    main(*sys.argv[1:])
