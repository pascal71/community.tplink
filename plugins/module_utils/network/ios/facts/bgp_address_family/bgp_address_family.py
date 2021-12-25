# -*- coding: utf-8 -*-
# Copyright 2020 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

"""
The community.tplink.ios bgp_address_family fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from ansible.module_utils.six import iteritems
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)
from ansible_collections.community.tplink.plugins.module_utils.network.ios.rm_templates.bgp_address_family import (
    Bgp_address_familyTemplate,
)
from ansible_collections.community.tplink.plugins.module_utils.network.ios.argspec.bgp_address_family.bgp_address_family import (
    Bgp_address_familyArgs,
)


class Bgp_address_familyFacts(object):
    """ The community.tplink.ios_bgp_address_family facts class
    """

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = Bgp_address_familyArgs.argument_spec

    def get_bgp_address_family_data(self, connection):
        return connection.get("sh running-config | section ^router bgp")

    def _process_facts(self, objs):
        """ makes data as per the facts after data obtained from parsers
        """
        temp_af = []
        if objs.get("address_family"):
            for k, v in iteritems(objs["address_family"]):
                if (
                    k == "__"
                ):  # prepare dicts keys to operate on post spliting the keys
                    continue
                temp_dict = {}
                temp = [every for every in k.split("_") if every != ""]
                temp_dict["afi"] = temp.pop(0)
                if len(temp) > 1:
                    temp_dict["vrf"] = [
                        each.split(" ")[1] for each in temp if "vrf" in each
                    ][0]
                    temp_dict["safi"] = [
                        each for each in temp if "vrf" not in each
                    ][0]
                elif len(temp) == 1:
                    if "vrf" in temp[0]:
                        temp_dict["vrf"] = temp[0].split("vrf ")[1]
                    else:
                        temp_dict["safi"] = temp[0]
                neighbor = v.get("neighbor")

                if neighbor:

                    def _update_neighor_list(neighbor_list, temp, alter=None):
                        set = False
                        temp = utils.remove_empties(temp)
                        for each in neighbor_list:
                            if neighbor_identifier == each["address"]:
                                each.update(temp)
                                set = True
                        if not neighbor_list or not set:
                            if alter:
                                neighbor_list.extend(list(alter.values()))
                            else:
                                neighbor_list.append(temp)

                    neighbor_list, temp_param_list = [], []
                    temp, al = {}, {}
                    temp_param, neighbor_identifier = None, None

                    for each in neighbor:
                        if temp_param and not each.get(temp_param) and temp:
                            temp.update({temp_param: temp_param_list})
                            _update_neighor_list(neighbor_list, temp)
                            temp_param_list = []
                            temp = {}
                        if (
                            each.get("address")
                            or each.get("ipv6_address")
                            or each.get("tag")
                        ) != neighbor_identifier:
                            neighbor_identifier = (
                                each.get("address")
                                or each.get("ipv6_address")
                                or each.get("tag")
                            )
                            if "address" in each:
                                temp["address"] = neighbor_identifier
                            elif "ipv6_address" in each:
                                temp["ipv6_address"] = neighbor_identifier
                            else:
                                temp["tag"] = neighbor_identifier
                        temp.update(each)
                        if not al.get(
                            each.get("address")
                        ):  # adds multiple nighbors
                            al[each.get("address")] = each
                        else:
                            al.get(each.get("address")).update(each)
                        for param in [
                            "prefix_lists",
                            "route_maps",
                            "slow_peer",
                        ]:
                            param_val = each.get(param)
                            if param_val:
                                temp_param_list.append(param_val[0])
                                temp_param = param
                                break
                    if temp:
                        if temp_param:
                            temp.update({temp_param: temp_param_list})
                        _update_neighor_list(neighbor_list, temp, al)
                        temp_param_list = []
                        temp = {}
                    v["neighbor"] = neighbor_list
                v.update(temp_dict)
                temp_af.append(v)

            objs["address_family"] = temp_af

            objs["address_family"] = sorted(
                objs["address_family"], key=lambda k, sk="afi": k[sk]
            )
        return objs

    def populate_facts(self, connection, ansible_facts, data=None):
        """ Populate the facts for Bgp_address_family network resource

        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf

        :rtype: dictionary
        :returns: facts
        """
        facts = {}
        objs = []

        if not data:
            data = self.get_bgp_address_family_data(connection)

        # parse native config using the Bgp_address_family template
        bgp_af_parser = Bgp_address_familyTemplate(
            lines=data.splitlines(), module=self._module
        )
        objs = bgp_af_parser.parse()

        if objs:

            objs = self._process_facts(utils.remove_empties(objs))

            ansible_facts["ansible_network_resources"].pop(
                "bgp_address_family", None
            )

            params = utils.remove_empties(
                bgp_af_parser.validate_config(
                    self.argument_spec, {"config": objs}, redact=True
                )
            )

            facts["bgp_address_family"] = params["config"]
            ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts
