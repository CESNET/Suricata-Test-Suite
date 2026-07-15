"""
Author(s):  Matyáš Sedmidubský <matyas.sedmidubsky@cesnet.cz>

Copyright: (C) 2026 CESNET, z.s.p.o.
SPDX-License-Identifier: BSD-3-Clause
"""

from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Self

from ruamel.yaml import YAML
from yamlpath import Processor
from yamlpath.enums.yamlvalueformats import YAMLValueFormats
from yamlpath.wrappers import ConsolePrinter, NodeCoords


def update_recursively(destination: Dict, source: Dict, extend_lists=True) -> Dict:
    for k, v in source.items():
        if isinstance(v, dict):
            destination[k] = update_recursively(destination.get(k, {}), source)
        elif isinstance(v, list) and extend_lists and isinstance(destination[k], list):
            destination[k].extend(v)
        else:
            destination[k] = v
    return destination


class ConfigBuilder:
    __yaml: YAML
    __proc: Processor
    output: str

    def add_option(self, key: str, value: Any) -> Self:
        """
        Allows for nested keys to be added using dot notation, e.g. "app-layer.protocols.dns.tcp.enabled"
        Raises ValueError if the key already exists in the configuration, otherwise adds the key with the provided value
        """
        for nc in self.__proc.get_nodes(key):
            if nc.node is not None:
                raise ValueError(f"Key '{key}' already exists in the configuration")

        self.set_option(key, value)

        return self

    def extend_option(self, key: str, value: Any, force=False, mustexist=True) -> Self:
        """
        Allows for nested keys to be updated using dot notation, e.g. "app-layer.protocols.dns.tcp.enabled"
        Will extend lists and update dictionaries recursively, otherwise will raise an exception unless force=True
        """
        exists = False
        for nc in self.__proc.get_nodes(key):
            exists = True
            if nc.node is not None:
                print(nc.node)
                if isinstance(nc.node, list) and isinstance(value, list):
                    nc.node.extend(value)
                elif isinstance(nc.node, dict) and isinstance(value, dict):
                    update_recursively(nc.node, value)
                elif force:
                    nc.node = value
                else:
                    raise ValueError(
                        f"Key '{key}' already exists in the configuration and cannot be extended with {type(value)}"
                    )
            elif mustexist:
                raise ValueError(f"Key '{key}' does not exist in the configuration")

        if not exists and mustexist:
            raise ValueError(f"Key '{key}' does not exist in the configuration")

        return self

    def set_option(self, key: str, value: Any) -> Self:
        """
        Allows for nested keys to be set using dot notation, e.g. "app-layer.protocols.dns.tcp.enabled"
        """
        if isinstance(value, list):
            # force arrays
            self.delete_option(key)
            for i, item in enumerate(value):
                self.set_option(f"{key}[{i}]", item)
        elif isinstance(value, dict):
            self.__proc.set_value(key, "dummy-value")
            nodes: list[NodeCoords] = list(self.__proc.get_nodes(key))
            for nc in nodes:
                nc.parent[nc.parentref] = value
        elif isinstance(value, str):
            # force quotes
            self.__proc.set_value(key, value, value_format=YAMLValueFormats.DQUOTE)
        else:
            self.__proc.set_value(key, value)

        return self

    def delete_option(self, key: str) -> Self:
        """
        Allows for nested keys to be deleted using dot notation, e.g. "app-layer.protocols.dns.tcp.enabled"
        """
        for _ in self.__proc.delete_nodes(key):
            pass

        return self

    def with_params(self, params: Dict) -> Self:
        for k, v in params.items():
            if k == "queues" or k == "rx_descriptors":
                continue
            self.__proc.set_value(k, v, mustexist=True)

        return self

    def build(self) -> str:
        out = open(self.output, mode="w+")
        self.__yaml.dump(self.__proc.data, out)

        return self.output

    def __init__(self, output: str, input: str | None = None) -> None:
        self.output = output

        self.__yaml = YAML()
        self.__yaml.indent(sequence=4, offset=2)
        self.__yaml.preserve_quotes = True

        if input is not None:
            with open(input, mode="r") as f:
                data = self.__yaml.load(f)
        else:
            root_dir = Path(__file__).resolve().parent.parent
            default_config_path = root_dir / "default_suricata.yaml"
            with default_config_path.open(mode="r") as f:
                data = self.__yaml.load(f)

        log_args = SimpleNamespace(quiet=True, verbose=False, debug=False)
        log = ConsolePrinter(log_args)
        self.__proc = Processor(log, data)
