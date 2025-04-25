from copy import deepcopy
from typing import Dict, List, Set, Any, Union
from ..utils import plugin_base
from networkx import MultiGraph
from ..utils import openconfig
import re
import ipaddress

class StigValidatorRouter(plugin_base.TestPluginBase):

    def __init__(self) -> None:
        self.unused_interfaces:Dict[str, List[str]] = {}
        self.used_interfaces:Dict[str, List[str]] = {}
        self.used_unused_interfaces_set = False
        self.subinterfaces_for_used_interfaces:Dict[str,Dict[str,List[str]]] = {}
        self.internal_interfaces:Dict[str, Dict[str, List[str]]] = {}
        self.subinterfaces_for_used_interfaces_set = False

    def populate_used_unused_interfaces(self, net_graph: MultiGraph, interfaces: Dict[str, List[str]]) -> None:
        if not self.used_unused_interfaces_set:
            for node, int_list in interfaces.items():
                for interface in int_list:
                    if node+":"+interface in net_graph:
                        assert net_graph.degree[node+":"+interface] <= 1, "Degree values larger than 1 make no sense."
                        if net_graph.degree[node+":"+interface] == 1:
                            if node not in self.used_interfaces:
                                self.used_interfaces[node] = []
                            self.used_interfaces[node].append(interface)
                        else:
                            if node not in self.unused_interfaces:
                                self.unused_interfaces[node] = []
                            self.unused_interfaces[node].append(interface)
                    else:
                        if node not in self.unused_interfaces:
                            self.unused_interfaces[node] = []
                        self.unused_interfaces[node].append(interface)
            self.used_unused_interfaces_set = True
    
    def get_all_subinterfaces_for_used_interface(self, config_files:Dict[str, Dict[str, Any]])-> None:
        if not self.subinterfaces_for_used_interfaces_set:
            for node, int_list in self.used_interfaces.items():
                if node in config_files:
                    self.subinterfaces_for_used_interfaces[node] = {}
                    self.internal_interfaces[node] = {}
                    int_set = set(int_list)
                    assert "openconfig-interfaces" in config_files[node], "Interfaces Model Missing"
                    for name, interface_obj in config_files[node]["openconfig-interfaces"].interfaces.interface.items():
                        if name in int_set:
                            self.subinterfaces_for_used_interfaces[node][name] = [str(index) for index in interface_obj.subinterfaces.subinterface]
                        else:
                            self.internal_interfaces[node][name] = [str(index) for index in interface_obj.subinterfaces.subinterface]
            self.subinterfaces_for_used_interfaces_set = True

    def name(self) -> str:
        return "StigValidatorRouter"
    
    def dummy_test(self, net_graph: MultiGraph, config_files: Dict[str, Dict[str, Any]], interfaces: Dict[str, List[str]], clients: Dict[str, Any]) -> List[Union[plugin_base.TestNotice,plugin_base.TestResult]]:
        return [plugin_base.TestSuccess("Dummy Test Succeeded")]
    
    def acl_coverage_check(self, net_graph: MultiGraph, config_files: Dict[str, Dict[str, Any]], interfaces: Dict[str, List[str]], clients: Dict[str, Any]) -> List[Union[plugin_base.TestNotice,plugin_base.TestResult]]:
        self.populate_used_unused_interfaces(net_graph, interfaces)
        self.get_all_subinterfaces_for_used_interface(config_files)
        missing_acl = []
        for node, config in config_files.items():
            assert "openconfig-acl" in config, "ACL Model Missing"
            acl_model = config["openconfig-acl"]
            # Generate list of all interfaces and subinterfaces with a vaild ACL
            # ACLs can be in any direction
            interface_subinterface_with_valid_acl = {}
            for interface_obj in acl_model.acl.interfaces.interface.values():
                if len(interface_obj.ingress_acl_sets.ingress_acl_set) > 0:
                    for acl_set_name_type in interface_obj.ingress_acl_sets.ingress_acl_set:
                        assert acl_set_name_type in acl_model.acl.acl_sets.acl_set, f"Invalid acl set {acl_set_name_type}"
                    if interface_obj.interface_ref.config.interface not in interface_subinterface_with_valid_acl:
                        interface_subinterface_with_valid_acl[interface_obj.interface_ref.config.interface] = set()
                    if not interface_obj.interface_ref.config.subinterface._changed():
                        interface_subinterface_with_valid_acl[interface_obj.interface_ref.config.interface].add(None)
                    else:
                        interface_subinterface_with_valid_acl[interface_obj.interface_ref.config.interface].add(interface_obj.interface_ref.config.subinterface)
                        
                if len(interface_obj.egress_acl_sets.egress_acl_set) > 0:
                    for acl_set_name_type in interface_obj.egress_acl_sets.egress_acl_set:
                        assert acl_set_name_type in acl_model.acl.acl_sets.acl_set, f"Invalid acl set {acl_set_name_type}"
                    if interface_obj.interface_ref.config.interface not in interface_subinterface_with_valid_acl:
                        interface_subinterface_with_valid_acl[interface_obj.interface_ref.config.interface] = set()
                    if not interface_obj.interface_ref.config.subinterface._changed():
                        interface_subinterface_with_valid_acl[interface_obj.interface_ref.config.interface].add(None)
                    else:
                        interface_subinterface_with_valid_acl[interface_obj.interface_ref.config.interface].add(interface_obj.interface_ref.config.subinterface)
            interface_subinterface_missing_acl = []
            for interface, subif_list in self.subinterfaces_for_used_interfaces[node].items():
                if interface not in interface_subinterface_with_valid_acl or None not in interface_subinterface_with_valid_acl[interface]:
                    interface_subinterface_missing_acl.append((node, interface, None))
                for subif in subif_list:
                    if interface not in interface_subinterface_with_valid_acl or subif not in interface_subinterface_with_valid_acl[interface]:
                        interface_subinterface_missing_acl.append((node, interface, subif))
            for interface, subif_list in self.internal_interfaces[node].items():
                if interface not in interface_subinterface_with_valid_acl or None not in interface_subinterface_with_valid_acl[interface]:
                    interface_subinterface_missing_acl.append((node, interface, None))
                for subif in subif_list:
                    if interface not in interface_subinterface_with_valid_acl or subif not in interface_subinterface_with_valid_acl[interface]:
                        interface_subinterface_missing_acl.append((node, interface, subif))
            missing_acl += interface_subinterface_missing_acl
        if len(missing_acl) > 0:
            return [plugin_base.TestFailure(f"CAT II: Missing ACLs for interfaces: {missing_acl}.")]
        return [plugin_base.TestSuccess("No interfaces missing ACLs.")]

    # https://bgpfilterguide.nlnog.net/guides/bogon_prefixes/   
    BOGON_PREFIXES_LIST_IPV4 = [
        ipaddress.ip_network("0.0.0.0/8"), # RFC 1122 ‘this’ network
        ipaddress.ip_network("10.0.0.0/8"), # RFC 1918 private space
        ipaddress.ip_network("100.64.0.0/10"), # RFC 6598 Carrier grade nat space
        ipaddress.ip_network("127.0.0.0/8"), # RFC 1122 localhost
        ipaddress.ip_network("169.254.0.0/16"), # RFC 3927 link local
        ipaddress.ip_network("172.16.0.0/12"), # RFC 1918 private space
        ipaddress.ip_network("192.0.2.0/24"), # RFC 5737 TEST-NET-1
        ipaddress.ip_network("192.88.99.0/24"), # RFC 7526 6to4 anycast relay
        ipaddress.ip_network("192.168.0.0/16"), # RFC 1918 private space
        ipaddress.ip_network("198.18.0.0/15"), # RFC 2544 benchmarking
        ipaddress.ip_network("198.51.100.0/24"), # RFC 5737 TEST-NET-2
        ipaddress.ip_network("203.0.113.0/24"), # RFC 5737 TEST-NET-3
        ipaddress.ip_network("224.0.0.0/4"), # multicast
        ipaddress.ip_network("240.0.0.0/4"), # reserved
    ]

    BOGON_PREFIXES_LIST_IPV6 = [
        ipaddress.ip_network("0100::/64"), # RFC 6666 Discard-Only
        ipaddress.ip_network("2001:2::/48"), # RFC 5180 BMWG
        ipaddress.ip_network("2001:10::/28"), # RFC 4843 ORCHID
        ipaddress.ip_network("2001:db8::/32"), # RFC 3849 documentation
        ipaddress.ip_network("2002::/16"), # RFC 7526 6to4 anycast relay
        ipaddress.ip_network("3ffe::/16"), # RFC 3701 old 6bone
        ipaddress.ip_network("3fff::/20"), # RFC 9637 documentation
        ipaddress.ip_network("5f00::/16"), # RFC 9602 SRv6 SIDs
        ipaddress.ip_network("fc00::/7"), # RFC 4193 unique local unicast
        ipaddress.ip_network("fe80::/10"), # RFC 4291 link local unicast
        ipaddress.ip_network("fec0::/10"), # RFC 3879 old site local unicast
        ipaddress.ip_network("ff00::/8"), # RFC 4291 multicast
    ]

    def bgp_bogon_route_policy_check(self, net_graph: MultiGraph, config_files: Dict[str, Dict[str, Any]], interfaces: Dict[str, List[str]], clients: Dict[str, Any]) -> List[Union[plugin_base.TestNotice,plugin_base.TestResult]]:
        nodes_missing_route_policy = []
        node_neighbor_missing_policy_application = []
        for node, config in config_files.items():
            assert "openconfig-network-instance" in config, "Network instance model missing"
            ninst_obj = config["openconfig-network-instance"]
            to_check = []
            # This check only applies if bgp has been configured
            for nist_name, net_instance in ninst_obj.network_instances.network_instance.items():
                for protocol_obj in net_instance.protocols.protocol.values():
                    if protocol_obj.identifier == "BGP":
                        to_check.append((nist_name, protocol_obj))
            if len(to_check) == 0:
                continue
            # Start Checking by searching for the appropriate route policy/policies
            assert "openconfig-routing-policy" in config, "Routing policy model missing"
            rpol_obj = config["openconfig-routing-policy"]
            valid_policy_set = set()
            valid_policy_set_ipv4 = set()
            valid_policy_set_ipv6 = set()
            for pol_name, policy_obj in rpol_obj.routing_policy.policy_definitions.policy_definition.items():
                cur_missing_prefixes_ipv4 = set(deepcopy(self.BOGON_PREFIXES_LIST_IPV4))
                cur_missing_prefixes_ipv6 = set(deepcopy(self.BOGON_PREFIXES_LIST_IPV6))
                for stmt_obj in policy_obj.statements.statement.values():
                    if stmt_obj.conditions.match_prefix_set._changed() and stmt_obj.conditions.match_prefix_set.config.prefix_set._changed() \
                        and (stmt_obj.conditions.match_prefix_set.config.match_set_options == "ANY" or (stmt_obj.conditions.match_prefix_set.config.match_set_options == "" and stmt_obj.conditions.match_prefix_set.config.match_set_options.default() == "ANY"))\
                        and stmt_obj.actions.config.policy_result == "REJECT_ROUTE":
                        assert stmt_obj.conditions.match_prefix_set.config.prefix_set in rpol_obj.routing_policy.defined_sets.prefix_sets.prefix_set, f"Invalid prefix set {stmt_obj.conditions.match_prefix_set.config.prefix_set} specified."
                        for prefix_obj in rpol_obj.routing_policy.defined_sets.prefix_sets.prefix_set[stmt_obj.conditions.match_prefix_set.config.prefix_set].prefixes.prefix.values():
                            ip_addr = ipaddress.ip_network(prefix_obj.ip_prefix)
                            if prefix_obj.masklength_range != "exact":
                                start_end = re.split('\.\.', prefix_obj.masklength_range, 1)
                                ip_addr_split = prefix_obj.ip_prefix.split("/")
                                if int(start_end[0]) != int(ip_addr_split[1]):
                                    ip_addr = ipaddress.ip_network(ip_addr_split[0]+"/"+start_end[0])
                            if isinstance(ip_addr, ipaddress.IPv4Network):
                                for i in self.BOGON_PREFIXES_LIST_IPV4:
                                    if i in cur_missing_prefixes_ipv4:
                                        if ip_addr == i or ip_addr.supernet_of(i):
                                            cur_missing_prefixes_ipv4.remove(i)
                            else:
                                for i in self.BOGON_PREFIXES_LIST_IPV6:
                                    if i in cur_missing_prefixes_ipv6:
                                        if ip_addr == i or ip_addr.supernet_of(i):
                                            cur_missing_prefixes_ipv6.remove(i)
                if len(cur_missing_prefixes_ipv4) == 0 and len(cur_missing_prefixes_ipv6) == 0:
                    valid_policy_set.add(pol_name)
                elif len(cur_missing_prefixes_ipv4) == 0:
                    valid_policy_set_ipv4.add(pol_name)
                elif len(cur_missing_prefixes_ipv6) == 0:
                    valid_policy_set_ipv6.add(pol_name)
            if len(valid_policy_set) == 0 and (len(valid_policy_set_ipv4) == 0 or len(valid_policy_set_ipv6) == 0):
                nodes_missing_route_policy.append((node, [item[0] for item in to_check]))
            else:
                # Check each neigbor on each bgp network-instance
                for nist_name, protocol_obj in to_check:
                    for neighbor_name, neighbor_obj in protocol_obj.bgp.neighbors.neighbor.items():
                        # We require that the policy be in the base level of the neighbor or peer group as opposed to in the afi-safi section since that corresponds most closely with the STIG guides
                        found = False
                        found_ipv4 = False
                        found_ipv6 = False
                        for policy in neighbor_obj.apply_policy.config.import_policy:
                            if policy in valid_policy_set:
                                found = True
                                break
                            if policy in valid_policy_set_ipv4:
                                found_ipv4 = True
                            if policy in valid_policy_set_ipv6:
                                found_ipv6 = True
                        if not found and (not found_ipv4 or not found_ipv6):
                            # Try checking the peer group to see if the route policy is there
                            if neighbor_obj.config.peer_group._changed():
                                assert neighbor_obj.config.peer_group in protocol_obj.bgp.peer_groups.peer_group, f"Invalid peer group {neighbor_obj.config.peer_group}"
                                for policy in protocol_obj.bgp.peer_groups.peer_group[neighbor_obj.config.peer_group].apply_policy.config.import_policy:
                                    if policy in valid_policy_set:
                                        found = True
                                    if policy in valid_policy_set_ipv4:
                                        found_ipv4 = True
                                    if policy in valid_policy_set_ipv6:
                                        found_ipv6 = True
                            if not found and (not found_ipv4 or not found_ipv6):
                                node_neighbor_missing_policy_application.append((node, nist_name, neighbor_name))
        if len(nodes_missing_route_policy) > 0 or len(node_neighbor_missing_policy_application) > 0:
            return [plugin_base.TestFailure(f"CAT II: Missing Bogon Route Policy '{nodes_missing_route_policy}' and/or missing application of bogon route policy '{node_neighbor_missing_policy_application}'.")]
        return [plugin_base.TestSuccess(f"No BGP routers with missing bogon route policy.")]


    JUMP_TABLE = {
        "DUMMY_TEST": dummy_test,
        "SRG-NET-000018-RTR-000001:ACL_COVERAGE_TEST": acl_coverage_check,
        "SRG-NET-000018-RTR-000002:BGP_BOGON_POLICY_CHECK": bgp_bogon_route_policy_check
    }
    def test_set(self) -> Set[str]:
        return set(self.JUMP_TABLE.keys())
    
    def run_one_test(self, test_name: str, net_graph: MultiGraph, config_files: Dict[str, Dict[str, Any]], interfaces: Dict[str, List[str]], clients: Dict[str, Any]) -> List[Union[plugin_base.TestNotice,plugin_base.TestResult]]:
        return self.JUMP_TABLE[test_name](self, net_graph, config_files, interfaces, clients)