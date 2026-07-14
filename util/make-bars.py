import sys
import json
import logging
import numpy as np
import argparse
import matplotlib.pyplot as plt
from dataclasses import dataclass
import time

logger = logging.getLogger(__name__)


@dataclass
class GraphBar:
    max_speed: float


@dataclass
class ResultsRow:
    tx_time: float = 0.0
    tx_bytes: int = 0
    tx_packets: int = 0
    rx_bytes: int = 0
    rx_packets: int = 0
    rx_rte_flow_filtered_packets: int = 0


def parse_row(data):
    return ResultsRow(
        tx_time=float(data["transmit_seconds"]),
        tx_bytes=int(data["trex_tx_bytes"]),
        tx_packets=int(data["trex_tx_packets"]),
        rx_bytes=int(data["suricata_rx_bytes"]),
        rx_packets=int(data["suricata_rx_packets"]),
        rx_rte_flow_filtered_packets=int(data["suricata_rte_flow_filtered_packets"]),
    )


def process_result_line(stats, graph_bar):
    THRESHOLD = 0.5
    result_from_row = parse_row(stats)

    BITS_PER_BYTE = 8
    BITS_PER_GIGABIT = 10**9

    max_speed = (
        result_from_row.tx_bytes
        * BITS_PER_BYTE
        / (result_from_row.tx_time * BITS_PER_GIGABIT)
    )

    logger.debug("Received packets total: %s", result_from_row.rx_packets)
    logger.debug("Transmitted packets total: %s", result_from_row.tx_packets)

    dropped_pkts: int = result_from_row.tx_packets - (
        result_from_row.rx_packets + result_from_row.rx_rte_flow_filtered_packets
    )
    logger.debug("Dropped packets total: %s", dropped_pkts)

    packet_loss = (
        100 * dropped_pkts / result_from_row.tx_packets
        if result_from_row.tx_packets != 0
        else 0
    )
    logger.debug("Packet loss in percentages: %s", packet_loss)
    if packet_loss < THRESHOLD:
        graph_bar.max_speed = max_speed
        return True
    else:
        return False


def get_max_speed(graph_bars):
    max_speed = 0
    for graph_bar in graph_bars:
        if graph_bar.max_speed > max_speed:
            max_speed = graph_bar.max_speed
    return max_speed + 3


def plot_graph(graph_bars, network_cards):
    species = (
        [card.strip() for card in network_cards.split(",")] if network_cards else []
    )
    no_rules = []
    software_rules = []
    rte_flow_rules = []

    for i in range(0, len(graph_bars), 3):
        assert i + 2 < len(graph_bars), "not enough data"
        no_rules.append(graph_bars[i].max_speed)
        software_rules.append(graph_bars[i + 1].max_speed)
        rte_flow_rules.append(graph_bars[i + 2].max_speed)

    tests = {
        "All traffic": tuple(no_rules),
        "Software rules": tuple(software_rules),
        "Rte_flow rules": tuple(rte_flow_rules),
    }

    x = np.arange(len(species))  # [0,1]
    width = 0.20
    multiplier = 0

    fig, ax = plt.subplots(figsize=(6, 4), layout="constrained")

    for attribute, measurement in tests.items():
        offset = width * multiplier
        rects = ax.bar(x + offset, measurement, width, label=attribute)
        ax.bar_label(rects, padding=3)
        multiplier += 1

    ax.set_ylabel("Maximum speed (Gbs)")
    ax.set_title("Packet drops according to Suricata and network card")
    ax.set_xticks(x + width, species)
    ax.set_ylim(0, get_max_speed(graph_bars))
    ax.axhline(
        y=get_max_speed(graph_bars),
        color="green",
        linestyle="-.",
        linewidth=1,
        alpha=0.3,
    )
    ax.legend(loc="upper center", ncols=3)

    time_format: str = "-".join(["%Y", "%m", "%d", "%H:%M"])

    plt.savefig(f"result{time.strftime(time_format)}.png", dpi=150)


def main(files, network_cards):
    graph_bars = []
    for file in files:
        graph_bar = GraphBar(0)
        graph_bars.append(graph_bar)
        with open(file, "r") as json_file:
            first = True
            logger.debug("Input file: %s", file)

            for line in json_file:
                agg_dict: dict = json.loads(line)
                if agg_dict.get("event", "") == "test_info":
                    continue
                elif agg_dict.get("event", "") == "test_results":
                    can_continue = process_result_line(agg_dict, graph_bar)
                    if can_continue is False and first is False:
                        break
                    first = False

    plot_graph(graph_bars, network_cards)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
    # warning -> the order of json matters -> without rules, Suricata software rules, rte_flow rules FIRT MELANOX, THEN ICE
    if len(sys.argv) < 1:
        raise SyntaxError("Insufficient arguments.")

    parser = argparse.ArgumentParser(
        usage='%(prog)s -n|--network_cards "MLX5,ICE" [path to aggregated1.json] [path to aggregated2.json] ...'
    )
    parser.add_argument("-n", "--network_cards", required=True)
    parser.add_argument("files", nargs="+")
    args = parser.parse_args()
    logger.debug("Files: %s | Network cards: %s", args.files, args.network_cards)
    main(args.files, args.network_cards)  # everything without the name of the program
