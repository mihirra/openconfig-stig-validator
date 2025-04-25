#!/usr/bin/env python3
import json
import os
import sys
import importlib
from typing import Dict, Any, List, Optional, cast
from networkx.drawing.nx_pydot import read_dot
from networkx import MultiGraph
import pyangbind.lib.pybindJSON as pbJ
from pyangbind.lib.yangtypes import safe_name
from pyangbind.lib.serialise import pybindIETFXMLDecoder
from . import openconfig
from . import plugin_base
import xmltodict

STANDARD_PLUGINS = [(None, "netconfvalidator.plugins.stig_validator_router")]
#TODO: Find some way to do this automatically
TOP_LEVEL_TO_MODEL_NAME={
    "acl":"openconfig-acl",
    "flows":"openconfig-ate-flow",
    "bfd":"openconfig-bfd",
    "organizations":"openconfig-module-catalog",
    "defined-sets": "openconfig-defined-sets",
    "transceiver-descriptors": "openconfig-terminal-device-properties",
    "linecard-descriptors": "openconfig-terminal-device-properties",
    "operational-mode-descriptors": "openconfig-terminal-device-properties",
    "ethernet-segments":"openconfig-ethernet-segments",
    "ha-groups": "openconfig-fw-high-availability",
    "interfaces": "openconfig-interfaces",
    "keychains":"openconfig-keychain",
    "lacp": "openconfig-lacp",
    "lldp": "openconfig-lldp",
    "macsec": "openconfig-macsec",
    "ipsec": "openconfig-ipsec",
    "network-instances": "openconfig-network-instance",
    "oam":"openconfig-oam",
    "channel-monitors":"openconfig-channel-monitor",
    "optical-amplifier":"openconfig-optical-amplifier",
    "optical-attenuator":"openconfig-optical-attenuator",
    "terminal-device":"openconfig-terminal-device",
    "connections":"openconfig-transport-line-connectivity",
    "aps":"openconfig-transport-line-protection",
    "wavelength-router":"openconfig-wavelength-router",
    "components":"openconfig-platform",
    "routing-policy":"openconfig-routing-policy",
    "probes":"openconfig-probes",
    "ptp":"openconfig-ptp",
    "qos":"openconfig-qos",
    "relay-agent":"openconfig-relay-agent",
    "sampling":"openconfig-sampling",
    "stp":"openconfig-spanning-tree",
    "system":"openconfig-system",
    "telemetry-system":"openconfig-telemetry",
    "access-points":"openconfig-access-points",
    "provision-aps":"openconfig-ap-manager",
    "joined-aps":"openconfig-ap-manager",
    "ssids":"openconfig-wifi-mac",
    "radios":"openconfig-wifi-phy",
    # Can't include IETF interfaces module due to conflict
}

#TODO: Find some way to do this automatically
MODEL_NAME_TO_TOP_LEVEL = {
    "openconfig-acl":["acl"],
    "openconfig-ate-flow":["flows"],
    "openconfig-bfd":["bfd"],
    "openconfig-module-catalog":["organizations"],
    "openconfig-defined-sets":["defined-sets"],
    "openconfig-terminal-device-properties":["transceiver-descriptors", "linecard-descriptors", "operational-mode-descriptors"],
    "openconfig-ethernet-segments":["ethernet-segments"],
    "openconfig-fw-high-availability":["ha-groups"],
    "openconfig-interfaces":["interfaces"],
    "openconfig-keychain":["keychains"],
    "openconfig-lacp":["lacp"],
    "openconfig-lldp":["lldp"],
    "openconfig-macsec":["macsec"],
    "openconfig-ipsec":["ipsec"],
    "openconfig-network-instance":["network-instances"],
    "openconfig-oam":["oam"],
    "openconfig-channel-monitor":["channel-monitors"],
    "openconfig-optical-amplifier":["optical-amplifier"],
    "openconfig-optical-attenuator":["optical-attenuator"],
    "openconfig-terminal-device":["terminal-device"],
    "openconfig-transport-line-connectivity":["connections"],
    "openconfig-transport-line-protection":["aps"],
    "openconfig-wavelength-router":["wavelength-router"],
    "openconfig-platform":["components"],
    "openconfig-routing-policy":["routing-policy"],
    "openconfig-probes":["probes"],
    "openconfig-ptp":["ptp"],
    "openconfig-qos":["qos"],
    "openconfig-relay-agent":["relay-agent"],
    "openconfig-sampling":["sampling"],
    "openconfig-spanning-tree":["stp"],
    "openconfig-system":["system"],
    "openconfig-telemetry":["telemetry-system"],
    "openconfig-access-points":["access-points"],
    "openconfig-ap-manager":["provision-aps", "joined-aps"],
    "openconfig-wifi-mac":["ssids"],
    "openconfig-wifi-phy":["radios"],
    # Can't include IETF interfaces module due to conflict
}

class Runner:

    @staticmethod
    def load_node_config_file(directory:str, filename:str) -> Dict[str, Any]:
        if not os.path.exists(directory + "/" + filename):
            raise RuntimeError(f"File path {directory + '/' + filename} must exist.")
        tmp = {}
        res = {}
        ext = os.path.splitext(directory + "/" + filename)[1]
        with open(directory + "/" + filename, "rt") as f:
            if  ext == ".xml":
                tmp = xmltodict.parse(f)
            elif ext == ".json":
                tmp = json.load(f)
            else:
                raise RuntimeError("Unsupported file format.")
        for key in tmp:
            key:str
            tmp_key = key
            model_name = None
            if key not in TOP_LEVEL_TO_MODEL_NAME:
                if ":" in key:
                    found = False
                    for elem in key.split(":"):
                        if elem in MODEL_NAME_TO_TOP_LEVEL:
                            model_name = elem
                            tmp_key = None
                            found = True
                            break
                        elif elem in TOP_LEVEL_TO_MODEL_NAME:
                            tmp_key = elem
                            model_name = None
                            found = True
                            break
                    if not found:
                        raise RuntimeError(f"Unrecognized key {key}")
                else:
                    raise RuntimeError(f"Unrecognized key {key}")
            if tmp_key is not None and TOP_LEVEL_TO_MODEL_NAME[tmp_key] in res:
                continue
            elif model_name is not None and model_name in res:
                continue
            else:
                cur_obj = {}
                assert tmp_key is None or model_name is None
                for cur_key in MODEL_NAME_TO_TOP_LEVEL[TOP_LEVEL_TO_MODEL_NAME[tmp_key] if tmp_key is not None else model_name]:
                    if cur_key in tmp:
                        cur_obj[cur_key] = tmp[cur_key]
                    elif model_name is not None and model_name + ":" + cur_key in tmp:
                        cur_obj[model_name + ":" + cur_key] = tmp[model_name + ":" + cur_key]
                if ext == ".json":
                    res[TOP_LEVEL_TO_MODEL_NAME[tmp_key] if tmp_key is not None else model_name] = pbJ.loads_ietf(json.dumps(cur_obj), openconfig, TOP_LEVEL_TO_MODEL_NAME[tmp_key] if tmp_key is not None else model_name)
                elif ext == ".xml":
                    res[TOP_LEVEL_TO_MODEL_NAME[tmp_key] if tmp_key is not None else model_name] = pybindIETFXMLDecoder.decode(xmltodict.unparse(cur_obj), openconfig, TOP_LEVEL_TO_MODEL_NAME[tmp_key] if tmp_key is not None else model_name)
                else:
                    # Shouldn't get here
                    raise RuntimeError("Unsupported file format.")
        for model_name in MODEL_NAME_TO_TOP_LEVEL.keys():
            if model_name not in res:
                # Code directly from pyangbind
                base_mod_cls = getattr(openconfig, safe_name(model_name))
                res[model_name] = base_mod_cls(path_helper=False)
        return res
    
    @staticmethod
    def load_client_config_file(directory:str, filename:str) -> Any:
        if not os.path.exists(directory + "/" + filename):
            raise RuntimeError(f"File path {directory + '/' + filename} must exist.")
        res = {}
        with open(directory + "/" + filename, "rt") as f:
            res = json.load(f)
        return res

    @staticmethod
    def import_plugin(path:Optional[str], mod_name:str) -> plugin_base.TestPluginBase:
        if path is not None and path not in sys.path:
            sys.path.append(path)
        for obj in importlib.import_module(mod_name).__dict__.values():
            if isinstance(obj, type) and issubclass(obj, plugin_base.TestPluginBase):
                return obj()
        raise RuntimeError(f"Plugin load failed for path {path} and module name {mod_name}")


    def __init__(self, directory:str, conf_file:Optional[str]=None) -> None:
        if not os.path.exists(directory+"/nodes.json"):
            raise RuntimeError("Directory for data to test must contain nodes.json")
        nodes_data = {}
        with open(directory+"/nodes.json", "rt") as f:
            nodes_data = json.load(f)
        if "map" not in nodes_data:
            raise RuntimeError("nodes.json must contain a map file.")
        else:
            self.__map = cast(MultiGraph, read_dot(directory + "/" + nodes_data["map"]))
        if "nodes" not in nodes_data:
            raise RuntimeError("nodes.json must contain data on all nodes in the system")
        else:
            self.__config_files = {}
            self.__interfaces = {}
            for elem in nodes_data["nodes"]:
                self.__config_files[elem["name"]] = Runner.load_node_config_file(directory, elem["filename"])
                self.__interfaces[elem["name"]] = elem["interfaces"]
        self.__clients = {}
        if "clients" in nodes_data:
            for elem in nodes_data["clients"]:
                self.__clients[elem["name"]] = Runner.load_client_config_file(directory, elem["filename"])
                self.__interfaces[elem["name"]] = elem["interfaces"]
        
        self.__plugins:Dict[str, plugin_base.TestPluginBase] = {}
        total_test_set = set()
        total_test_dict = {}
        self.__tests:Dict[str, List[str]] = {}
        for path, mod_name in STANDARD_PLUGINS:
            obj = Runner.import_plugin(path, mod_name)
            self.__plugins[obj.name()] = obj
            total_test_set |= obj.test_set()
            total_test_dict[obj.name()] = list(obj.test_set())
        if conf_file is not None and os.path.exists(conf_file):
            conf_data = {}
            with open(conf_file, "rt") as f:
                conf_data = json.load(f)
            if "plugins" in conf_data:
                for path in conf_data["plugins"]:
                    obj = Runner.import_plugin(os.path.dirname(path), os.path.splitext(os.path.basename(path))[0])
                    self.__plugins[obj.name()] = obj
                    total_test_set |= obj.test_set()
                    total_test_dict[obj.name()] = list(obj.test_set())
            if "tests" in conf_data:
                for test_name in conf_data["tests"]:
                    if test_name in total_test_set:
                        for name, test_list in total_test_dict:
                            if test_name in test_list:
                                if name not in self.__tests:
                                    self.__tests[name] = []
                                self.__tests[name].append(test_name)
            else:
                self.__tests = total_test_dict
        else:
            self.__tests = total_test_dict


    def run_tests(self) -> None:
        for name, test_list in self.__tests.items():
            for test in test_list:
                try:
                    print(f"Running test {test}:")
                    ret = self.__plugins[name].run_one_test(test, self.__map, self.__config_files, self.__interfaces, self.__clients)
                    assert len(ret) >= 1 and isinstance(ret[-1], plugin_base.TestResult), "FAILURE: No result for test given."
                    for elem in ret:
                        elem.print()
                except AssertionError as e:
                    print(e.with_traceback())

