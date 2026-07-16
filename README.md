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
  - [8. Defining new tests](#8-defining-new-tests)
  - [9. Results and graphs](#9-results-and-graphs)
  - [10. Logging](#10-logging)
  - [11. Troubleshooting](#11-troubleshooting)

---

## 1. Prerequisites

1. Local requirements are:
  - **Python 3.11**
  - pip
  - rsync
  - ssh with ssh-agent

2. **Set up the testing environment**:

You will need your local machine and two servers. These need to be reachable via ssh using your
username\* and ssh agent. Make sure that your servers have the appropriate drivers for your network
card and the network stack you will be using (i.e. `DPDK` or `AF_PACKET`) and that you have disabled
any unwanted behavior like `LLDP`, `TuneD` or disk swapping.

\*If you want to use a different username for `ssh` you need to set the `USER` variable in the command.
```bash
USER="ssh_user" ./pytest_start.sh ...
```
It should also be noted that the `USER` variable is a hard requirement, so any environemnts where it
isn't set by default (CI/CD usually) need it to be set to some valid username.

On the Suricata server, you need sudo access and [suricata installed](https://docs.suricata.io/en/latest/install.html)
in such a way that the `suricata` and `suricatasc` binaries are in your user's $PATH.

On the traffic generator server [install TRex](https://trex-tgn.cisco.com/trex/doc/trex_manual.html#_download_and_installation),
so that you have
[TRex daemons running on ports `8090`-`8093`](https://github.com/CESNET/lbr-testsuite/tree/master/lbr_testsuite/trex#setting-up-trex-for-trex-manager).
and that these ports are not being blocked by the firewall.

Some of these tests use TRex's ASTF mode (see below), which requires port mirroring on the switch that your servers are connected to.
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

---

### Trex modes

The TRex traffic generator has support for different ways of generating traffic:

- ASTF mode *(advanced stateful)*
  - all traffic is handled with a fully working TCP/IP stack
  - there are **two TRex instances** communicating together as server and client
  - allows for creating complex profiles combining several PCAPs
- STL mode *(stateless)*
  - there is only one TRex instance that creates traffic and sends it to DUT (a server running Suricata in our case)
  - operates on profiles with streams, where each stream has a different packet template and rate of transmission
    - packet templates can be as simple as a static packet being sent on repeat or can implement different
      rules using the TRex field engine to modify the packet before it's sent
  - replaying PCAPs is limited to one per port and doesn't support dynamically modifying them
- STF mode *(stateful)*
  - mixture of the ASTF and STL modes
  - one TRex instance sending out traffic based on a profile
  - useful for mixing PCAPs into traffic sent over one port
  - main disadvantage is that PCAPs need to be transferred to the remote server

Each mode has its own strengths but STF and ASTF are most interesting for our use case, since they allow for
defining traffic with PCAP files.

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
# Variables marked with "# -" don't have any default value, otherwise
# default values are shown

# Mandatory flags
# if these aren't set, you have to manually specify them every time
DEFAULT_SURICATA_SERVER="claret"  # -
DEFAULT_TREX_SERVER="trex2"       # -
DEFAULT_TREX_PORT1="0000:b3:00.0" # -
DEFAULT_TREX_PORT2="0000:b3:00.1" # -
DEFAULT_PCIES="0000:3b:00.0"      # -

# Mandatory for single port tests
DEFAULT_TARGET_MAC="08:C0:EB:88:C5:38" # -

# Optional flags
DEFAULT_TARGET_VLAN=15                     # -
DEFAULT_TESTS="http_simple nfs_smb_simple" # all tests by default
DEFAULT_TIME=300
DEFAULT_HEATUP=0
DEFAULT_HUGEPAGES="6G"
LOGLEVEL="INFO"
```

Note that an empty string ("") in `-d` (or `DEFAULT_TESTS`) is a valid value for running all tests
and that setting `DEFAULT_TESTS` will prevent you from doing so.

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
    --param-file="param.py" \
    --traffic-duration=300 \
    -s --suite-log-level=info \
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

### pcap_replay

This is a special case where TRex will read one pcap file and send it to Suricata over one port.
The test can be controlled directly from `pytest_start.sh` or `python3.11 -m pytest` flags.
The relevant flags are:

- for `pytest_start.sh`:
  - `--target-mac`
  - `--target-vlan`
  - `--pcap`
- for direct pytests:
  - `--target-mac`
  - `--target-vlan`
  - `--pcap-replay`

You can learn more about these from the respective `--help` messages.

This test uses the STL TRex mode, so it only replays the PCAP with a new MAC address. If you
need to change the VLAN that the packets are tagged with, pytest will create a new PCAP with
the new VLAN hardcoded. Another notable property of the test (and STL TRex in general) is
that packets are sent at a constant rate. This means that there are 0.5 microseconds between
packets at 1x multiplier (so ~2 million pps) and this doesn't change with packet size.

---

### Binary search

This is a mode where we are testing maximum Suricata throughput and trying to converge on a defined
packet drop rate. The search returns the highest found multiplier that is under or equal the specified
allowed drop rate. If none is found, the run fails (raises `MultiplierNotFoundError`).

Binary search is enabled by passing positional arguments to `--binary-search`. All four
arguments are **required** — passing `-bs` with no arguments will result in an error.

```bash
--binary-search <mm> <xm> <dr> <pr>
```

| Position | Name | Type | Description |
|---|---|---|---|
| `mm` | min-multiplier | FLOAT | Lowest bound of the search range |
| `xm` | max-multiplier | FLOAT | Highest bound of the search range |
| `dr` | drop-rate | FLOAT | Target drop rate in % `<0, 100>` |
| `pr` | precision | FLOAT | Exit when `(xm - mm) < precision` |

Examples:
```bash
# All 4 required values:
pytest ... --binary-search 0.0 10.0 1.0 0.05

# Via pytest_start.sh:
./pytest_start.sh ... -bs 0.0 10.0 1.0 0.05
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
2. **Modify config** — Apply parameter values from `param.py` to the Suricata YAML config.
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

### Binary search

Binary search cycles through each `param.py` combination. The test execution flow is:

1. **Setup** — Allocate hugepages, bind NIC, modify Suricata config.
2. **Start Suricata** — Launch as a daemon on the remote host via SSH.
3. **Start TRex** — Begin traffic at the current midpoint multiplier.
4. **Wait** — Traffic runs for the configured duration (`--traffic-duration`).
5. **Stop TRex** — Stop traffic generation.
6. **Stop Suricata** — SIGTERM, fetch `eve.json` statistics.
7. **Save results** — Record throughput and drop rate for this multiplier.
8. **Converge** — Use the measured drop rate; adjust the search bounds (min or max) and repeat
   from step 2 with a new midpoint until `(max - min) < precision`.

Progress output will look similar to this:

```
[PROGRESS] ------ Cycle: 1 ------- [PROGRESS]
[Progress] multiplier 5.0000 | param_file=param.py | params={'dpdk.interfaces[0].interface': '0000:05:00.0', 'dpdk.interfaces[0].mtu': 3000}
Running command: suricata -c /tmp/suricata-1783523849/suricata.yaml -l /var/log/suricata -S /var/lib/suricata/rules/suricata.rules -D --dpdk --pidfile /var/run/suricata.pid
[INFO] Drop rate: 72.7429%.

[PROGRESS] ------ Cycle: 2 ------- [PROGRESS]
...

[FINISH] Maximum multiplier found is: 4.5000. | param_file=param.py | params={...}
```

---

## 8. Defining new tests

When creating a new test you should follow the structure described above. There are several helpers to streamline this process.

The initial setup should be already handled with pytest autouse fixtures, but if it fails for your hardware check `bind` in `conftest.py`.

Tests have a baseline `norules` variant and a `rules` variant which loads `/var/lib/suricata/rules/suricata.rules`.
To achieve this you can use pytest parametrization, which allows you to define the test flow once and use it for both variants.
The parametrization is done with a snippet like this:
```python
@pytest.mark.parametrize("rules_config", [
    {"name": "norules", "path": "/dev/null/"},
    {"name": "rules", "path": "/var/lib/suricata/rules/suricata.rules"}
], ids=["norules", "rules"])
```
Where you will need to add a `rules_config` parameter to your test function and fetch the test variant and Suricata rules path from there.

To modify the Suricata config you should use the `ConfigBuilder` class as this has a shorthand for using `params.py` - `builder.with_params(params)`
and in general simplifies the process of modifying the config from python.
If you expect to be adding new keys to the config - you don't want to overwrite any existing keys - you should use the
`builder.add_option(...)` method as this will notify you when this key already exists.
See `util/config_builder.py` for other methods.

Interfacing with Suricata and TRex is done with `Suricata_manager` and an instance of a TRex profile respectively.

For details check out any of the existing tests as they are usually quite short and shouldn't be too difficult to understand now.

---

### Defining TRex profiles

When defining the profile you should first decide which TRex mode you want to target. This will likely be STF or ASTF.
To understand the differences you can read the note in [prerequisites](#1-prerequisites) or the official documentation
for [STF](https://trex-tgn.cisco.com/trex/doc/trex_manual.html), [ASTF](https://trex-tgn.cisco.com/trex/doc/trex_astf.html)
or [STL](https://trex-tgn.cisco.com/trex/doc/trex_stateless.html).

For **all modes** you will want to create a subclass of `BaseTrexClientManager` and pass a list with tuples of paths to individual
pcaps and "weights" of the pcaps. See the comment under `BaseTrexClientManager` for the interpretations of weights in the
individual TRex modes.

If you want to place files into a specific directory on your remote server you can redefine the `get_remote_data_path` function
which gets called for every file that gets sent to the remote.

When defining an **ASTF profile** you likely want to define the `get_astf_profile` method which is used to retrive an `ASTFProfile` object.
This can either be a standalone function which creates the profile from scratch or it can use a "native" TRex profile file. The latter
is preferred as it leads to simpler tuning and debugging. For examples see `http_trex_profile`.

When defining an **STF profile** you might want to define `get_stf_profile` which should return a path to a
[traffic profile](https://trex-tgn.cisco.com/trex/doc/trex_manual.html#_traffic_yaml_f_argument_of_stateful).
You should generate these dynamically, since the profile contains MAC addresses and a mismatch will cause
your packets to not be delivered.

You might also want to change some things in the [platform config](https://trex-tgn.cisco.com/trex/doc/trex_manual.html#_platform_yaml_cfg_argument)
which can be done by defining an `stf_config_hook`. This function gets a `ConfigBuilder` instance with the config that would be sent to
trex and you can either modify this or create a completely new `ConfigBuilder` instance.
For examples see `realistic_traffic_trex_profile.py`

**STL profiles** are defined only with a list of PCAPs and should really only be used as a simple fallback, but STF is preferred
and can be used in the same situations as STL.

You are not limited to one TRex mode per profile. For example you can define a TRex profile that has a native ASTF TRex config, which is used for
the ASTF mode and `get_stf_profile` uses it to create an STF profile dynamically.

---

## 9. Results and graphs

Results are saved to `results/artefacts/{timestamp}/{test_name}/`.

To compare results across multiple runs, use `util/make-graphs.py`:

```bash
python3.11 util/make-graphs.py results/run1/aggregated_results.json results/run2/aggregated_results.json
```

Graphs are saved to `results/graphs/`.

---

## 10. Logging

This test suite uses structured logging for debugging, monitoring, and troubleshooting. Logs are emitted to both the console and optional log files, with configurable verbosity levels.

### Log Levels

| Level      | Description                                                                 |
|------------|-----------------------------------------------------------------------------|
| **DEBUG**  | Detailed internal information (e.g., variable values, algorithm steps).     |
| **INFO**   | General operational messages (e.g., test start/completion, authentication). |
| **PROGRESS**| High-level progress updates (e.g., cycle numbers, iteration counts).       |
| **WARNING**| Non-critical issues that don't stop execution but may need attention.       |
| **ERROR**  | Serious problems that prevent a specific operation from completing.         |
| **CRITICAL**| Severe errors that may cause the entire test suite to fail.                |

### Configuration

Logging behavior is controlled via command-line options:

- `--suite-log-level <LEVEL>`  
  Set the minimum level shown on console (default: `INFO`).  
  Example: `--suite-log-level=DEBUG` shows all messages including debug details.

- `--suite-log-file`  
  Enable writing logs to file. When set, logs are saved to:  
  `results/artefacts/<timestamp>/pytest.log`

### Tips

- Keep console at `INFO` for clean progress tracking during normal runs.
- Always check `pytest.log` for full debug history if tests fail unexpectedly.
- Library loggers (paramiko, fabric, invoke, faker) are automatically suppressed to avoid duplicate output.

---

## 11. Troubleshooting

| Problem | Solution |
|---------|----------|
| `ConnectionRefusedError` on TRex port 8093 | TRex daemon is not running. |
| `ValueError: No match found for ...` | Server/PCIe combination missing from `test_settings.json`. Add an entry for your server and PCIe address. |
| Suricata won't start | Check `/var/log/suricata/suricata.log` on the Suricata server. |
| Hugepages not allocated | Check with `cat /proc/meminfo \| grep HugePages` on the Suricata server. |
| NIC not bound to correct driver | Run `dpdk-devbind -s` on the Suricata server to check driver bindings. |
| `sudo -E sh -c 'lshw -c network \| grep -c <PCIe> > /tmp/pcie_count'` has failed with code 1. | Check your PCIes for typos |
