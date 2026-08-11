#!/usr/bin/python3
"""
Author(s):  Dávid Hanko <david.hanko@cesnet.cz>

Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause

Generic visualisation of Suricata counter values from stats/eve.json files.

Reads one or more eve.json (or eve-stats.json) files, filters the per-line
``stats`` records with a universal jq filter, extracts the requested counter
paths and plots them over time (using ``.stats.uptime`` as the x-axis).

Example:
    python3 util/visualize.py -i stats.json -p flow.memuse -p stream.memuse \\
        -f 'uptime > 30'

Multiple input files can be given (each ``-i`` adds another file); each input
is plotted as its own labelled series on the same plot.

When several series have very different Y scales (e.g. ``pkts`` next to
``bytes``), the smaller ones are automatically moved to a secondary Y axis so
they are not flattened out of view. Use ``--no-secondary-axis`` to disable
this, or ``--secondary-axis-threshold`` to tune the detection.
"""

import argparse
import json
import logging
import math
import sys
from pathlib import Path
from typing import List, Tuple

import jq
import matplotlib.pyplot as plt

logger = logging.getLogger(__name__)

# Format strings (marker + linestyle) cycled across series so that, in
# addition to color, each series is distinguishable by marker and line style.
# This helps accessibility (e.g. colour-blind viewers) when several series are
# plotted together. The color itself is still assigned from the shared color
# generator in _plot.
_SERIES_FORMATS = [
    "o-",   # circle, solid
    "s--",  # square, dashed
    "^:",   # triangle_up, dotted
    "D-.",  # diamond, dash-dot
    "v-",   # triangle_down, solid
    "P--",  # plus (filled), dashed
    "X:",   # x (filled), dotted
    "h-.",  # hexagon1, dash-dot
]

# Set once the first time _summarize_series warns about too few points for
# --delta, so the warning is not repeated for every multiplier run.
_warned_delta_insufficient = False

# jq keywords that can appear as the leading token of a filter. When a filter
# starts with one of these, it is a jq construct (not a field access), so
# _normalize_filter must not prepend a '.'.
_JQ_KEYWORDS = frozenset(
    {
        "as",
        "break",
        "catch",
        "def",
        "elif",
        "else",
        "end",
        "foreach",
        "if",
        "import",
        "label",
        "module",
        "reduce",
        "select",
        "then",
        "try",
    }
)


def _parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Plot Suricata counter values from stats/eve.json files. "
            "Each input file is treated as JSON-lines; only records with "
            "event_type == 'stats' are considered."
        )
    )
    parser.add_argument(
        "-i",
        "--input",
        action="append",
        required=True,
        metavar="FILE",
        help=(
            "Input stats/eve.json file (JSON-lines). May be given multiple "
            "times; each input is plotted as its own labelled series."
        ),
    )
    parser.add_argument(
        "-p",
        "--path",
        action="append",
        required=True,
        metavar="PATH",
        help=(
            "Counter path relative to .stats, e.g. 'flow.memuse' or "
            "'capture.dpdk.imissed'. May be given multiple times to plot "
            "several counters."
        ),
    )
    parser.add_argument(
        "-f",
        "--filter",
        default="",
        metavar="JQ",
        help=(
            "Universal jq filter applied to each stats record (e.g. "
            "'uptime > 30'). The filter is evaluated against the .stats "
            "object; records for which it does not match are skipped."
        ),
    )
    parser.add_argument(
        "-o",
        "--output",
        default=None,
        metavar="FILE",
        help="Optional output file for the plot (e.g. graph.png).",
    )
    parser.add_argument(
        "-x",
        "--x-axis",
        default="uptime",
        metavar="PATH",
        help=(
            "Counter path (relative to .stats) used as the x-axis. Default: "
            "'uptime'. Ignored in --by-multiplier mode, where the x-axis is "
            "always the traffic multiplier."
        ),
    )
    parser.add_argument(
        "--title",
        default=None,
        help="Optional plot title.",
    )
    parser.add_argument(
        "--delta",
        action="store_true",
        help=(
            "Plot the difference between consecutive samples instead of the "
            "raw cumulative counter value. Suricata stats counters are "
            "cumulative (they only increase), so plotting them directly gives "
            "a straight line; --delta shows the per-interval rate instead."
        ),
    )
    parser.add_argument(
        "--by-multiplier",
        action="store_true",
        help=(
            "Plot a summary value of each counter against the traffic "
            "multiplier instead of against uptime. The input must be a test "
            "directory containing multiplier_*/eve-stats.json files. "
            "For each multiplier the counter's final value is plotted (or, "
            "with --delta, its peak per-interval rate). The -x/--x-axis "
            "option is ignored in this mode."
        ),
    )
    parser.add_argument(
        "--no-secondary-axis",
        action="store_true",
        help=(
            "Disable the automatic secondary Y axis. By default, when several "
            "series have very different Y scales (e.g. pkts vs bytes), the "
            "flattened series are moved to a secondary Y axis so they remain "
            "visible. This flag keeps everything on a single axis."
        ),
    )
    parser.add_argument(
        "--secondary-axis-threshold",
        type=float,
        default=0.1,
        metavar="FRACTION",
        help=(
            "Fraction of the combined Y range below which a series is moved "
            "to the secondary Y axis. A series whose own Y range is smaller "
            "than this fraction of the combined range is considered flattened "
            "by the other series. Default: 0.1 (10%%)."
        ),
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )
    args = parser.parse_args(argv)
    if not (0 < args.secondary_axis_threshold <= 1):
        parser.error("--secondary-axis-threshold must be in the range (0, 1]")
    return args


def _read_stats_records(path: Path) -> List[dict]:
    """Read all ``stats`` event records from a JSON-lines file."""
    records: List[dict] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                logger.warning("Skipping malformed JSON line in %s", path)
                continue
            if obj.get("event_type") == "stats":
                records.append(obj)
    return records


def _apply_filter(records: List[dict], filter_expr: str) -> List[dict]:
    """Keep only records whose ``.stats`` matches the given jq filter."""
    if not filter_expr:
        return records
    # jq parses a leading bare identifier (e.g. ``uptime > 30``) as a function
    # call, not a field access. Prepend ``.`` so the common ``uptime > 30``
    # form works as ``.uptime > 30`` without requiring the user to type it.
    filter_expr = _normalize_filter(filter_expr)
    try:
        compiled = jq.compile(filter_expr)
    except ValueError as exc:
        logger.error("Invalid jq filter %r: %s", filter_expr, exc)
        return []
    filtered: List[dict] = []
    for rec in records:
        stats = rec.get("stats")
        if stats is None:
            continue
        try:
            result = compiled.input(stats).first()
        except (ValueError, TypeError) as exc:  # jq raises on invalid input
            logger.warning("jq filter failed on a record: %s", exc)
            continue
        # jq returns None for a non-matching select() and False for a boolean
        # expression that evaluates to false. A numeric 0 is NOT treated as a
        # non-match, so a bare-value filter (e.g. ``uptime``) keeps records
        # where the value is 0.
        if result is None or result is False:
            continue
        filtered.append(rec)
    return filtered


def _normalize_filter(filter_expr: str) -> str:
    """Prepend ``.`` to a leading bare identifier in a jq filter.

    ``uptime > 30`` becomes ``.uptime > 30`` so field access works without the
    user having to type the leading dot. Filters that already start with a
    jq construct (``.``, ``[``, ``(``, ``{``, ``select``, etc.) or with a
    function call (e.g. ``has("foo")``) are left as-is.
    """
    stripped = filter_expr.lstrip()
    if not stripped:
        return filter_expr

    # Preserve any leading whitespace so it is not lost when we prepend the
    # dot to the first identifier token (e.g. ' uptime > 30' -> ' .uptime > 30').
    leading_ws = filter_expr[: len(filter_expr) - len(stripped)]

    # Consume the leading identifier token (letters, digits, underscores).
    i = 0
    while i < len(stripped) and (stripped[i].isalnum() or stripped[i] == "_"):
        i += 1
    if i == 0:
        return filter_expr

    ident = stripped[:i]
    if not (ident[0].isalpha() or ident[0] == "_"):
        return filter_expr

    rest = stripped[i:].lstrip()
    # Leave jq keywords and function calls (identifier followed by '(') alone;
    # only bare field identifiers get a leading '.' prepended.
    if ident in _JQ_KEYWORDS or rest.startswith("("):
        return filter_expr

    return f"{leading_ws}.{stripped}"


def _compile_path(path: str) -> "jq._Program":
    """Compile a jq program that reads ``.stats.<path>`` from a record."""
    return jq.compile(f".stats.{path}")


def _extract_series(
    records: List[dict],
    x_compiled: "jq._Program",
    y_compiled: "jq._Program",
    x_path: str,
    y_path: str,
) -> List[Tuple[float, float]]:
    """Extract aligned (x, y) points for a counter path across all records.

    ``x_compiled`` and ``y_compiled`` are pre-compiled jq programs (see
    ``_compile_path``) that read the x-axis value and the counter value from
    a record. Both are evaluated on the *same* record, so the returned points
    are always aligned even when some records are missing one of the paths. A
    record is skipped (with a warning) only if either value cannot be
    extracted.
    """
    points: List[Tuple[float, float]] = []
    for rec in records:
        try:
            x_value = x_compiled.input(rec).first()
            y_value = y_compiled.input(rec).first()
        except (ValueError, TypeError) as exc:  # jq raises on invalid input
            logger.warning(
                "Failed to extract %r/%r from a record: %s", x_path, y_path, exc
            )
            continue
        if x_value is None or y_value is None:
            continue
        try:
            x_f = float(x_value)
            y_f = float(y_value)
        except (TypeError, ValueError):
            logger.warning(
                "Non-numeric %r/%r value in a record (x=%r, y=%r); skipping.",
                x_path,
                y_path,
                x_value,
                y_value,
            )
            continue
        points.append((x_f, y_f))
    return points


def _to_delta(points: List[Tuple[float, float]]) -> List[Tuple[float, float]]:
    """Convert a cumulative series into per-interval deltas.

    Suricata stats counters are cumulative (they only increase), so plotting
    them directly yields a straight line. This converts each point to the
    difference from the previous sample, i.e. the amount accumulated in that
    interval (a proxy for the rate). The first point is dropped since it has
    no predecessor.

    Note: if Suricata restarts mid-run, a cumulative counter can decrease,
    producing a negative delta. Callers that reduce the series to a single
    value (e.g. ``_summarize_series`` with ``max``) are unaffected, but a
    ``--delta`` plot will show a sharp negative dip at the restart.
    """
    deltas: List[Tuple[float, float]] = []
    for i in range(1, len(points)):
        x_prev, y_prev = points[i - 1]
        x_cur, y_cur = points[i]
        deltas.append((x_cur, y_cur - y_prev))
    return deltas


def _find_multiplier_dirs(test_dir: Path) -> List[Tuple[float, Path]]:
    """Find ``multiplier_*/eve-stats.json`` files under a test dir.

    Returns a list of ``(multiplier, eve_stats_path)`` sorted by multiplier.

    The multiplier is parsed from the directory name suffix after
    ``multiplier_`` (e.g. ``multiplier_2.5`` -> ``2.5``). Directories whose
    suffix is not a valid float (e.g. ``multiplier_2.5x``) are skipped with a
    warning, as are directories without an ``eve-stats.json``.
    """
    found: List[Tuple[float, Path]] = []
    for sub in sorted(test_dir.iterdir()):
        if not sub.is_dir() or not sub.name.startswith("multiplier_"):
            continue
        try:
            multiplier = float(sub.name.split("_", 1)[1])
        except ValueError:
            logger.warning("Skipping non-numeric multiplier dir: %s", sub.name)
            continue
        stats_path = sub / "eve-stats.json"
        if stats_path.is_file():
            found.append((multiplier, stats_path))
    found.sort(key=lambda item: item[0])
    return found


def _summarize_series(points: List[Tuple[float, float]], use_delta: bool) -> float:
    """Reduce a counter series to a single summary value.

    Without ``use_delta`` returns the final (last) cumulative value. With
    ``use_delta`` returns the peak per-interval rate (max delta), which is a
    better proxy for the sustained throughput at a given multiplier.

    Returns ``float("nan")`` when there is nothing to summarise (empty input,
    or ``use_delta`` with fewer than two points, since a delta needs a
    predecessor).
    """
    if not points:
        return float("nan")
    if use_delta:
        if len(points) < 2:
            global _warned_delta_insufficient
            if not _warned_delta_insufficient:
                _warned_delta_insufficient = True
                logger.warning(
                    "Some series have fewer than 2 points for --delta; need at "
                    "least 2 to compute a rate. Returning NaN for those."
                )
            return float("nan")
        deltas = _to_delta(points)
        return max((d[1] for d in deltas), default=float("nan"))
    return float(points[-1][1])


def _split_secondary_axis(
    series: List[Tuple[str, List[Tuple[float, float]]]],
    threshold: float,
) -> Tuple[
    List[Tuple[str, List[Tuple[float, float]]]],
    List[Tuple[str, List[Tuple[float, float]]]],
]:
    """Split series into primary and secondary Y-axis groups.

    A series is moved to the secondary axis when its own Y range is a small
    fraction of the combined Y range across all series, i.e. it is "flattened"
    by the scale of the other series (e.g. ``pkts`` next to ``bytes``, or
    ``flow.memuse`` next to ``tcp.memuse``). Returns ``(primary, secondary)``.

    Degenerate cases are handled conservatively: with fewer than two series,
    or when the combined range is zero (all values identical), nothing is
    split. A constant series (own range zero) is kept on the primary axis,
    since a secondary axis cannot make a flat line non-flat.
    """
    if len(series) < 2:
        return series, []

    all_ys = [y for _, points in series for _, y in points]
    combined_range = max(all_ys) - min(all_ys)
    if combined_range == 0:
        return series, []

    primary: List[Tuple[str, List[Tuple[float, float]]]] = []
    secondary: List[Tuple[str, List[Tuple[float, float]]]] = []
    for name, points in series:
        ys = [y for _, y in points]
        series_range = max(ys) - min(ys)
        if series_range > 0 and series_range < threshold * combined_range:
            secondary.append((name, points))
        else:
            primary.append((name, points))
    return primary, secondary


def _plot(
    series: List[Tuple[str, List[Tuple[float, float]]]],
    x_label: str,
    y_label: str,
    title: str | None,
    output: str | None,
    secondary_axis: bool = True,
    secondary_threshold: float = 0.1,
) -> bool:
    """Plot the given series.

    When ``secondary_axis`` is enabled, series whose Y scale is much smaller
    than the combined scale are plotted on a secondary Y axis (see
    ``_split_secondary_axis``) so they are not flattened out of view.

    Returns ``True`` if at least one series had data and a plot was produced,
    ``False`` if every series was empty (in which case no figure is created).
    """
    # Drop NaN values (e.g. a multiplier run with no data) so they do not
    # produce broken/gapped points in the plot. A series whose points are all
    # NaN is treated as empty.
    valid_series = [
        (name, [(x, y) for x, y in points if not math.isnan(y)])
        for name, points in series
    ]
    non_empty = [(name, points) for name, points in valid_series if points]
    if not non_empty:
        logger.error("No series have data to plot.")
        return False

    if secondary_axis:
        primary, secondary = _split_secondary_axis(non_empty, secondary_threshold)
    else:
        primary, secondary = non_empty, []

    fig, ax = plt.subplots()
    ax2 = ax.twinx() if secondary else None
    # Share a single color generator and a single format-string generator
    # between the primary and secondary axes so colors and marker/line styles
    # do not repeat across them (each axis would otherwise restart the default
    # cycles).
    colors = iter(plt.rcParams["axes.prop_cycle"].by_key()["color"])
    formats = iter(_SERIES_FORMATS)
    for name, points in primary:
        xs = [p[0] for p in points]
        ys = [p[1] for p in points]
        ax.plot(
            xs, ys, next(formats), label=name, markersize=3, color=next(colors)
        )
    if ax2 is not None:
        for name, points in secondary:
            xs = [p[0] for p in points]
            ys = [p[1] for p in points]
            ax2.plot(
                xs,
                ys,
                next(formats),
                label=f"{name} (secondary ax.)",
                markersize=3,
                color=next(colors),
            )
        ax2.set_ylabel(y_label)
    ax.set_xlabel(x_label)
    ax.set_ylabel(y_label)
    if title:
        ax.set_title(title)
    # Build the legend from both axes' lines so secondary-axis series appear
    # in it too.
    lines = ax.get_lines() + (ax2.get_lines() if ax2 is not None else [])
    ax.legend(lines, [line.get_label() for line in lines])
    ax.grid(True, linestyle="--", alpha=0.5)
    fig.tight_layout()
    if output:
        fig.savefig(output)
        logger.info("Plot saved to %s", output)
    else:
        plt.show()
    return True


def _append_file_series(
    series: List[Tuple[str, List[Tuple[float, float]]]],
    args: argparse.Namespace,
    file: Path,
) -> int:
    """Append one series per counter path for a single input stats file.

    Returns 1 on a fatal error (input file not found), else 0. A file with no
    usable records is skipped (logged) rather than treated as an error.
    """
    if not file.is_file():
        logger.error("Input file not found: %s", file)
        return 1
    records = _read_stats_records(file)
    logger.info("Read %d stats records from %s", len(records), file)
    if not records:
        logger.warning("No stats records in %s; skipping.", file)
        return 0

    # Apply the universal jq filter to this file's records.
    if args.filter:
        before = len(records)
        records = _apply_filter(records, args.filter)
        logger.info(
            "Filter %r kept %d/%d records in %s",
            args.filter,
            len(records),
            before,
            file,
        )
    if not records:
        logger.warning("No records remain in %s after filtering; skipping.", file)
        return 0

    # Compile the x-axis program once per file and reuse it for the presence
    # check and every counter path.
    x_compiled = _compile_path(args.x_axis)

    # Extract the x-axis series once per file to check it is present.
    x_points = _extract_series(
        records, x_compiled, x_compiled, args.x_axis, args.x_axis
    )
    if not x_points:
        logger.warning(
            "Could not extract x-axis path %r from %s; skipping.",
            args.x_axis,
            file,
        )
        return 0

    # One series per requested path, labelled with the source file so that
    # multiple inputs are distinguishable on the same plot. Use the parent
    # directory name (e.g. "multiplier_2.5") when present, since input files
    # are often all named eve-stats.json.
    label = file.parent.name if len(args.input) > 1 else ""
    for counter_path in args.path:
        # Extract x and y from the same record so they stay aligned even when
        # some records lack the counter path.
        y_compiled = _compile_path(counter_path)
        points = _extract_series(
            records, x_compiled, y_compiled, args.x_axis, counter_path
        )
        if not points:
            logger.warning(
                "Counter path %r extracted no values from %s; check for a typo.",
                counter_path,
                file,
            )
        if args.delta:
            points = _to_delta(points)
        name = f"{counter_path} ({label})" if label else counter_path
        series.append((name, points))
    return 0


def _append_multiplier_series(
    series: List[Tuple[str, List[Tuple[float, float]]]],
    args: argparse.Namespace,
    test_dir: Path,
) -> int:
    """Append one series per counter path for a single test directory.

    Each ``-i`` argument is a test directory containing ``multiplier_*/``
    subdirectories, each holding an ``eve-stats.json`` file. For every
    multiplier the requested counters are reduced to a single summary value
    (final value, or peak rate with ``--delta``) and plotted against the
    multiplier.

    Returns 1 on a fatal error (missing directory, or no multiplier runs),
    else 0.
    """
    if not test_dir.is_dir():
        logger.error("Test directory not found: %s", test_dir)
        return 1
    multipliers = _find_multiplier_dirs(test_dir)
    if not multipliers:
        logger.error("No multiplier_*/eve-stats.json found under %s", test_dir)
        return 1
    logger.info("Found %d multiplier runs under %s", len(multipliers), test_dir)

    label = test_dir.name if len(args.input) > 1 else ""
    # The x-axis is always the multiplier in this mode, so use a fixed
    # time-like field (uptime) for extraction. Compile it once per test
    # directory and reuse it for every counter and multiplier.
    x_compiled = _compile_path("uptime")
    for counter_path in args.path:
        y_compiled = _compile_path(counter_path)
        xs: List[float] = []
        ys: List[float] = []
        extracted_any = False
        for multiplier, stats_path in multipliers:
            records = _read_stats_records(stats_path)
            if args.filter:
                records = _apply_filter(records, args.filter)
            # Extract x and y from the same record so they stay aligned even
            # when some records lack the counter path.
            points = _extract_series(
                records, x_compiled, y_compiled, "uptime", counter_path
            )
            if points:
                extracted_any = True
            summary = _summarize_series(points, args.delta)
            xs.append(multiplier)
            ys.append(summary)
        if not extracted_any:
            logger.warning(
                "Counter path %r extracted no values from any multiplier "
                "run; check for a typo.",
                counter_path,
            )
        name = f"{counter_path} ({label})" if label else counter_path
        series.append((name, list(zip(xs, ys))))
    return 0


def main(argv: List[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    if args.by_multiplier and args.x_axis != "uptime":
        logger.warning(
            "--x-axis is ignored in --by-multiplier mode; the x-axis is "
            "always the traffic multiplier."
        )

    # Process each input independently. In normal mode an input is a stats
    # file and each counter is plotted as a full time series; in
    # --by-multiplier mode an input is a test directory and each counter is
    # reduced to a summary value per multiplier run.
    series: List[Tuple[str, List[Tuple[float, float]]]] = []
    for input_path in args.input:
        path = Path(input_path)
        if args.by_multiplier:
            status = _append_multiplier_series(series, args, path)
        else:
            status = _append_file_series(series, args, path)
        if status != 0:
            return status

    if not series:
        logger.error("No data to plot from the given input files.")
        return 1

    if args.by_multiplier:
        x_label = "multiplier"
        y_label = "peak per-interval rate" if args.delta else "final counter value"
    else:
        x_label = args.x_axis
        y_label = "per-interval rate" if args.delta else "counter value"

    if not _plot(
        series,
        x_label,
        y_label,
        args.title,
        args.output,
        secondary_axis=not args.no_secondary_axis,
        secondary_threshold=args.secondary_axis_threshold,
    ):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
