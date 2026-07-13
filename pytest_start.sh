#!/usr/bin/env bash

set -xe

usage(){
  set +x
  echo "Bash script to start pytest"
  echo "Options:"
  echo "-s | --server [SERVER] to specify the server, where Suricata will be running"
  echo "-tm | --target-mac [MAC_ADDRESS] to specify where to send traffic when not using ASTF TRex."
  echo "-tv | --target-vlan [VLAN_ID] to specify what VLAN tag to use for generated traffic."
  echo '-d | --defined-tests [TESTS] to specify tests, which have to be included, for all available tests run [-d|--defined-tests] " ",
  for specific tests: [-d|--defined-tests] "nfs_smb_simple https_simple" or use multiple parameter specification, for specific test from test file
  use [-d|--defined-tests] https_simple/test_https_simple.py::test_https_norules, by default it runs http_simple tests'
  echo "-t | --defined-time [TIME] to specify traffic duration in tests (seconds)"
  echo "-tg | --trex-server-hostname [TRAFFIC GENERATOR] to specify traffic generator server for testing"
  echo "-p1 | --trex-server-port-1 [TRAFFIC GENERATOR PORT] to specify traffic generator port"
  echo "-p2 | --trex-server-port-2 [TRAFFIC GENERATOR PORT] to specify traffic generator port"
  echo "-p | --pcie [PCIE] to specify, on which pcie will be Suricata tested, use multiple parameter specification or [-p|--pcie] "0000:3b:00.0 0000:3b:00.1""
  echo "-ht | --heatup [TIME] to specify the duration for which to wait before measuring statistics"
  echo "-f | --filter [rules/norules] starts Suricata with/without rules"
  echo "-pc | --pcap [PATH] to specify the pcap file to send to Suricata. Also sets --defined-tests to *only* pcap_replay"
  echo "-pm | --prefer-trex-mode [MODE] to suggest a mode for TRex. If unavailable tests use their defaults."
  echo "-fm | --force-trex-mode [MODE] to force a TRex mode. If unavailable tests get skipped. Overrides -pm"
  echo "-sh | --suricata-hugepages [SIZE] to specify how much RAM to allocate in hugepages. Default is 6G."
  exit 0
}

PYTHON="python3.11"

if [ -f ./.env ];  then
    source ./.env
fi

while [ "$#" -gt 0 ]; do
  case $1 in
    -s | --server) suricata_server=$2  ; shift 2  ;;
    -tm | --target-mac) target_mac=$2 ; shift 2 ;;
    -tv | --target-vlan) target_vlan=$2 ; shift 2 ;;
    -d | --defined-tests) defined_tests+=" "${2}; shift 2 ;;
    -t | --defined-time) defined_time=$2 ; shift 2 ;;
    -tg | --trex-server-hostname) trex_server_hostname=$2; shift 2 ;;
    -p1 | --trex-server-port-1) trex_server_port_1=$2; shift 2 ;;
    -p2 | --trex-server-port-2) trex_server_port_2=$2; shift 2 ;;
    -p | --pcie) pcies+=" "${2}; shift 2 ;;
    -ht | --heatup) heatup_duration=$2; shift 2 ;;
    -f | --filter) case $2 in rules) filter="rules and not norules";;
                        norules) filter="norules";;
                        *) filter="$2";;
		esac; shift 2 ;;
	-pc | --pcap) pcap_replay="$2"; shift 2 ;;
    -pm | --prefer-trex-mode) trex_mode_flags+="--prefer-trex-mode $2 "; shift 2 ;;
    -fm | --force-trex-mode) trex_mode_flags+="--force-trex-mode $2 "; shift 2 ;;
    -sh | --suricata-hugepages) hugepages="$2"; shift 2 ;;
    -h | --help) usage ; shift ;;
    --) shift; read -a extra_args <<< "$@"; break ;;
    *) >&2 echo unsupported option: $1
      usage
      exit 1
      ;;
  esac
done

if [ -z "$suricata_server" ]; then
    if [ ! -z "$DEFAULT_SURICATA_SERVER" ]; then
        suricata_server="$DEFAULT_SURICATA_SERVER"
    else
        echo "Error: No Suricata server specified. Use -s to provide a server hostname."
        exit 1
    fi
fi

if [ -z "$target_mac" ]; then
    if [ ! -z "$DEFAULT_TARGET_MAC" ]; then
        target_mac="$DEFAULT_TARGET_MAC"
    else
        echo "Warning: No target MAC address specified. Some tests require this."
    fi
fi

if [ -z "$target_vlan" ]; then
    if [ ! -z "$DEFAULT_TARGET_VLAN" ]; then
        target_vlan="$DEFAULT_TARGET_VLAN"
    else
        target_vlan=0
    fi
fi

if [ -z "$trex_server_hostname" ]; then
    if [ ! -z "$DEFAULT_TREX_SERVER" ]; then
        trex_server_hostname="$DEFAULT_TREX_SERVER"
    else
        echo "Error: No TRex server specified. Use -tg to provide a server hostname."
        exit 1
    fi
fi

if [ -z "$trex_server_port_1" ]; then
    if [ ! -z "$DEFAULT_TREX_PORT1" ]; then
        trex_server_port_1="$DEFAULT_TREX_PORT1"
    else
        echo "Error: No TRex port 1 specified. Use -p1 to provide a port number."
        exit 1
    fi
fi

if [ -z "$trex_server_port_2" ]; then
    if [ ! -z "$DEFAULT_TREX_PORT2" ]; then
        trex_server_port_2="$DEFAULT_TREX_PORT2"
    else
        echo "Error: No TRex port 2 specified. Use -p2 to provide a port number."
        exit 1
    fi
fi

if [ ! -z "$pcap_replay" ]; then
    defined_tests="pcap_replay"
    extra_args+=("--pcap-replay")
    extra_args+=("$pcap_replay")
fi

if [ -z "$defined_tests" ]; then
    if [ ! -z "$DEFAULT_TESTS" ]; then
        defined_tests="$DEFAULT_TESTS"
    fi
fi

defined_tests=$(echo "$defined_tests" | awk '{
    # Trim leading and trailing whitespace
    gsub(/^[[:space:]]+|[[:space:]]+$/, "")

    # Prepend "tests/" if not already present
    for (i = 1; i <= NF; i++) {
        if ($i !~ /^tests\//) {
            $i = "tests/" $i
        }
    }

    print
}')

if [ -z "$defined_time" ]; then
    if [ ! -z "$DEFAULT_TIME" ]; then
        defined_time="$DEFAULT_TIME"
    else
        defined_time=300
    fi
fi

if [ -z "$heatup_duration" ]; then
    if [ ! -z "$DEFAULT_HEATUP" ]; then
        heatup_duration="$DEFAULT_HEATUP"
    else
        heatup_duration=0
    fi
fi

if [ -z "$pcies" ]; then
    if [ ! -z "$DEFAULT_PCIES" ]; then
        pcies="$DEFAULT_PCIES"
    else
        echo "Error: No PCIe addresses specified. Use -p to provide at least one PCIe address."
        exit 1
    fi
fi

if [ -z "$hugepages" ]; then
    if [ ! -z "$DEFAULT_HUGEPAGES" ]; then
        hugepages="$DEFAULT_HUGEPAGES"
    else
        hugepages="6G"
    fi
fi

if [ -z "$VIRTUAL_ENV" ]; then
    if [ -d ".venv" ]; then
        source ".venv/bin/activate"
    elif [ -d "../.venv" ]; then
        source "../.venv/bin/activate"
    elif [ -f "/home/local/$(whoami)/tmp" ]; then
        # legacy location
        source "/home/local/$(whoami)/tmp/bin/activate"
    else
        echo "Creating python virtual environment"
        $PYTHON -m venv .venv
        if [ $? -ne 0 ]; then
            echo "Failed to create .venv"
            exit 1
        fi
        source ".venv/bin/activate"
        pip install --upgrade pip
        if [ $? -ne 0 ]; then
            echo "Failed to upgrade pip"
            exit 1
        fi
        pip install -r requirements.txt
        if [ $? -ne 0 ]; then
            echo "Failed to install dependencies"
            exit 1
        fi
    fi
fi

read -a pcie_array <<< "$pcies"

mkdir -p bkp
cp param.py bkp/ && mv bkp/param.py bkp/param$(date +%Y_%m_%d).py

for pcie in "${pcie_array[@]}"
do
  sed "s/PCIEaddr/$pcie/" param_template.py > param.py
  $PYTHON -m pytest -s --log-level=info \
    --suricata-hugepages="$hugepages" \
    --target-mac="$target_mac" \
    --target-vlan="$target_vlan" \
    --trex-generator="$trex_server_hostname,$trex_server_port_1" \
    --trex-generator="$trex_server_hostname,$trex_server_port_2" \
    --remote-host="$suricata_server" --param-file="param.py" \
    --trex-force-use \
    $trex_mode_flags \
    --traffic-duration="$defined_time" \
    --heatup-duration="$heatup_duration" \
    -k "$filter" \
    $defined_tests "${extra_args[@]}"
done
