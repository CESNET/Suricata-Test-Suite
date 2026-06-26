# Suricata Performance Tests

Pytest-based performance tests for Suricata IDS/IPS. Tests measure maximum throughput
(packets/bytes) Suricata can process under various configurations using TRex traffic generators and
mirrored network traffic.

---

- [Suricata Performance Tests](#suricata-performance-tests)
  - [1. Prerequisites](#1-prerequisites)
  - [2. Running tests with pytest\_start.sh](#2-running-tests-with-pytest_startsh)
  - [3. Running tests directly with pytest](#3-running-tests-directly-with-pytest)
  - [4. Available tests](#4-available-tests)
  - [5. Parameter file (param.py)](#5-parameter-file-parampy)
  - [6. Test settings (test\_settings.json)](#6-test-settings-test_settingsjson)
  - [7. Test execution flow](#7-test-execution-flow)
  - [8. Results and graphs](#8-results-and-graphs)
  - [9. Troubleshooting](#9-troubleshooting)

---

## 1. Prerequisites

1. Local requirements are:
  - **Python 3.11**
  - pip
  - rsync
  - ssh with ssh-agent

2. **Set up the testing environment**:

You will need your local machine and two servers. These need to be reachable via ssh using your
username and ssh agent. Make sure that your servers have the appropriate drivers for your network
card and the network stack you will be using (i.e. `DPDK` or `AF_PACKET`) and that you have disabled
any unwanted behavior like `LLDP`, `TuneD` or disk swapping.

On the Suricata server, you need sudo access and [suricata installed](https://docs.suricata.io/en/latest/install.html)
in such a way that the `suricata` and `suricatasc` binaries are in your user's $PATH.

On the traffic generator server [install TRex](https://trex-tgn.cisco.com/trex/doc/trex_manual.html#_download_and_installation),
so that you have
[TRex daemons running on ports `8090`-`8093`](https://github.com/CESNET/lbr-testsuite/tree/master/lbr_testsuite/trex#setting-up-trex-for-trex-manager).
and that these ports are not being blocked by the firewall.

Some of these tests use TRex's ASTF mode, which requires port mirroring on the switch that your servers are connected to.
The ASTF mode works by having a server and a client TRex instance, which need to communicate with each other. At the same
time Suricata also needs to see this traffic, so you end up with something like this:
```
TRex server <--┬--> TRex client
               |
        (port mirroring)
               |
               v
            Suricata
```

3. **Set up the local environment**:

You only need to do this if you want to run pytest directly,
if you will be using the `pytest_start.sh` script, this is handled for you.

```bash
python3.11 -m venv .venv
source .venv/bin/activate # or your shell's variant
pip install --upgrade pip
pip install -r requirements.txt
```

4. Tests must be run from this (`suricata_pytests/`) directory.

---

## 2. Running tests with pytest_start.sh

The wrapper script `pytest_start.sh` handles parameter generation from `param_template.py` and virtual environment activation.

```bash
./pytest_start.sh -s <SURICATA_SERVER> -tg <TREX_SERVER> -d <TESTS> -t <DURATION> \
    -p <SURI_PCIE> -p1 <TREX_PCIE1> -p2 <TREX_PCIE2>
```

`<SURICATA_SERVER>` and `<TREX_SERVER>` can be hostnames or IP addresses that pytest will attempt to SSH into with your user, so make sure
you have appropriate SSH keys set up in your ssh agent.

Both `<TREX_PCIE1>` and `<TREX_PCIE2>` are required as the internal TRex manager doesn't retrieve them deterministically, so even
if you are running tests with TRex on only one port, you still need to set the second PCIe address (presumably to the same interface
as `<TREX_PCIE1>`).

If you want to pass a flag to pytest directly, you can do so by adding it after `--` like `./pytest_start.sh ... -- --collect-only`.

### Environment variables

Optionally you can create a `.env` file with default variables, so that you don't have to fill out the flags on every run of pytests.
The file will look like this: 

```bash
# Mandatory flags
DEFAULT_SURICATA_SERVER="claret"
DEFAULT_TREX_SERVER="trex2"
DEFAULT_TREX_PORT1="0000:b3:00.0"
DEFAULT_TREX_PORT2="0000:b3:00.1"
DEFAULT_PCIES="0000:3b:00.0"

# Optional flags
DEFAULT_TESTS="http_simple nfs_smb_simple"
DEFAULT_TIME=300
DEFAULT_HEATUP=10
```

### Examples

```bash
# Full run: collect tests in `tests/http_simple` and run each for 5 minutes.
./pytest_start.sh -s claret -tg trex2 -d http_simple -t 300 -p 0000:3b:00.0
# Note: the `-t` flag is interpreted by the individual test functions, which usually means that
# there is a for loop that runs the test multiple times with different TRex multipliers for `-t`
# seconds each.

# Quick run: run a single test function for 20s with rules
./pytest_start.sh -s dpdk-test2 -d http_simple -t 20 -tg trex -p 0000:05:00.0 /
	-p1 0000:65:00.0 -p2 0000:65:00.0 -f rules

# Multiple PCIe addresses
./pytest_start.sh -s claret -d http_simple -t 60 -p 0000:3b:00.0 -p 0000:af:00.0

# Multiple test suites
./pytest_start.sh -s claret -d http_simple -d https_simple -t 300 -p 0000:3b:00.0
```

**Note:** The script generates `param.py` from `param_template.py` by substituting the `PCIEaddr`
placeholder with the actual PCIe address before each pytest invocation.

---

## 3. Running tests directly with pytest

```bash
python3.11 -m pytest \
    --suricata-hugepages="4G" \
    --trex-generator="trex2,0000:b3:00.0" \
    --trex-generator="trex2,0000:b3:00.1" \
    --remote-host="claret" \
    --user="$(whoami)" \
    --param-file="param.py" \
    --traffic-duration=300 \
    -s --log-level=info \
    "tests/http_simple"
```

For all available pytest options, see `conftest.py::pytest_addoption` or run `python3.11 -m pytest --help`. For rules/norules testing, use '-k "norules"' or '-k "rules and not norules"'

## 4. Available tests

Each tests subdirectory (e.g., `http_simple/`, `https_simple/`) is a test suite. Every suite has `_norules` (baseline,
no inspection rules) and `_rules` (full ruleset) variants. Browse the test directories to see what's available, or run:

```bash
python3.11 -m pytest --collect-only
```

To run a specific test function, use syntax with -f [rules/norules]:

```bash
./pytest_start.sh -s claret -d http_simple -t 60 -p 0000:3b:00.0 -f rules
```

---

## 5. Parameter file (param.py)

The parameter file defines which Suricata configuration values to test. All combinations of parameter values are
generated via `itertools.product` and each combination becomes a separate pytest parametrize case (e.g., `params0`,
`params1`, ...).

### param_template.py

`pytest_start.sh` generates `param.py` from `param_template.py` by replacing the `PCIEaddr` placeholder:

### Full param.py example

```python
suri_yaml_params = {
    "dpdk.interfaces[0].interface": ["0000:3b:00.0"],
    "dpdk.interfaces[0].mtu": [2500, 3000],
    "dpdk.interfaces[0].rx-descriptors": [32768],
    "dpdk.interfaces[0].mempool-size": [1048575],
}

capture_modes = ["dpdk", "af-packet"]
suri_cmd_params = {"capture-mode": ["dpdk"]}

filter = {
    "dpdk": [lambda x: x["dpdk.interfaces[0].mtu"] <= 3000],
    "af-packet": [lambda x: True]
}
```

Keys in `suri_yaml_params` are YAML paths into the Suricata configuration file (`suricata.yaml`).
Values are lists — every combination is tested. With the example above, two parameter sets are
generated (one for MTU 2500, one for MTU 3000).

### Capture modes

- **DPDK** (default) — Direct hardware access via vfio-pci driver. Highest performance. Parameters use `dpdk.interfaces[N].*` keys.
- **AF_PACKET** — Kernel-based capture via standard Linux networking. Parameters use `af-packet[N].*` keys.

Set which modes to test via `suri_cmd_params`:

```python
# DPDK only (default)
suri_cmd_params = {"capture-mode": ["dpdk"]}

# AF_PACKET only
suri_cmd_params = {"capture-mode": ["af-packet"]}

# Both (runs all tests twice, once per mode)
suri_cmd_params = {"capture-mode": ["af-packet", "dpdk"]}
```

### Filtering parameter combinations

The `filter` dictionary defines per-capture-mode lambda functions to exclude invalid parameter combinations:

```python
filter = {
    "dpdk": [
        lambda x: x["dpdk.interfaces[0].mtu"] <= 3000,
        lambda x: x["dpdk.interfaces[0].rx-descriptors"] >= 4096,
    ],
    "af-packet": [lambda x: True]
}
```

All filter functions must return `True` for a combination to be included.

---

## 6. Test settings (test_settings.json)

Each test directory contains a `test_settings.json` that maps server + PCIe combinations to TRex traffic multipliers.
These multipliers control how fast TRex sends traffic in each iteration of a test.

```json
{
    "configuration": {
        "tests": [
            {
                "test_name": "test_http_norules",
                "servers": [
                    {
                        "server_name": "claret",
                        "pci": [
                            {
                                "pcie_addr": "0000:3b:00.0",
                                "trex_multipliers": [0.1, 0.2, 0.3, 0.5, 0.7, 1.0]
                            }
                        ]
                    }
                ]
            }
        ]
    }
}
```

The test function looks up multipliers by matching `test_name`, `server_name`, and `pcie_addr`.
If no match is found, the test fails with a `ValueError`.

### Adding a new server

To test on a new server/PCIe, add an entry to the `servers` array for **each test function** in the relevant `test_settings.json`:

```json
{
    "server_name": "dpdk-test2",
    "pci": [
        {
            "pcie_addr": "0000:05:00.0",
            "trex_multipliers": [0.1, 0.2, 0.3]
        }
    ]
}
```

---

## 7. Test execution flow

For each `param.py` combination (e.g., `params0`, `params1`), and for each multiplier defined in `test_settings.json`:

1. **Setup** (conftest.py) — Allocate hugepages on the Suricata server, bind NIC to the appropriate driver (vfio-pci for DPDK, ethtool for AF_PACKET).
2. **Modify config** — Apply parameter values from `param.py` to the Suricata YAML config via `yamlpath`.
3. **Start Suricata** — Launch as a daemon on the remote host via SSH.
4. **Start TRex** — Client and server begin traffic exchange at the current multiplier rate.
5. **Wait** — Traffic runs for the configured duration (`--traffic-duration`).
6. **Stop TRex** — Stop traffic generation.
7. **Stop Suricata** — Send SIGTERM, wait for graceful shutdown, fetch `eve.json` statistics.
8. **Save results** — Record throughput statistics for this multiplier.
9. **Repeat** — Move to the next multiplier.

Progress is printed during execution:

```
[Progress] multiplier 3/10 | param_file=param.py | params={'dpdk.interfaces[0].interface': '0000:05:00.0', 'dpdk.interfaces[0].mtu': 3000}
sending packets at 0.3 * default cps of .pcap
```

---

## 8. Results and graphs

Results are saved to `results/artefacts/{timestamp}/{test_name}/`.

To compare results across multiple runs, use `util/make-graphs.py`:

```bash
python3.11 util/make-graphs.py results/run1/aggregated_results.json results/run2/aggregated_results.json
```

Graphs are saved to `results/graphs/`.

---

## 9. Troubleshooting

| Problem | Solution |
|---------|----------|
| `ConnectionRefusedError` on TRex port 8093 | TRex daemon is not running. |
| `ValueError: could not convert string to float: ''` | Server/PCIe combination missing from `test_settings.json`. Add an entry for your server and PCIe address. |
| Suricata won't start | Check `/var/log/suricata/suricata.log` on the Suricata server. |
| Hugepages not allocated | Check with `cat /proc/meminfo \| grep HugePages` on the Suricata server. |
| NIC not bound to correct driver | Run `dpdk-devbind -s` on the Suricata server to check driver bindings. |
