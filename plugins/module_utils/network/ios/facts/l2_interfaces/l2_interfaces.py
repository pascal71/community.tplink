#
# -*- coding: utf-8 -*-
# Copyright 2019 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
"""
The ios interfaces fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

from copy import deepcopy
import re
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)
from ansible_collections.community.tplink.plugins.module_utils.network.ios.utils.utils import (
    get_interface_type,
    normalize_interface,
)
from ansible_collections.community.tplink.plugins.module_utils.network.ios.argspec.l2_interfaces.l2_interfaces import (
    L2_InterfacesArgs,
)


class L2_InterfacesFacts(object):
    """ The ios l2 interfaces fact class
    """

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = L2_InterfacesArgs.argument_spec
        spec = deepcopy(self.argument_spec)
        if subspec:
            if options:
                facts_argument_spec = spec[subspec][options]
            else:
                facts_argument_spec = spec[subspec]
        else:
            facts_argument_spec = spec

        self.generated_spec = utils.generate_dict(facts_argument_spec)

    def get_l2_interfaces_data(self, connection):
        return connection.get("show running-config")

    def populate_facts(self, connection, ansible_facts, data=None):
        """ Populate the facts for interfaces
        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf
        :rtype: dictionary
        :returns: facts
        """
        objs = []
        if not data:
            data = self.get_l2_interfaces_data(connection)

        # operate on a collection of resource x
        #config = ("\n" + data).split("\ninterface ")
        config = (data).split("\ninterface ")
        for conf in config:
            if conf:
                obj = self.render_config(self.generated_spec, conf)
                if obj:
                    objs.append(obj)

        facts = {}
        if objs:
            facts["l2_interfaces"] = []
            params = utils.validate_config(
                self.argument_spec, {"config": objs}
            )
            for cfg in params["config"]:
                facts["l2_interfaces"].append(utils.remove_empties(cfg))
        ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts

    def render_config(self, spec, conf):
        """
        Render config as dictionary structure and delete keys from spec for null values
        :param spec: The facts tree, generated from the argspec
        :param conf: The configuration
        :rtype: dictionary
        :returns: The generated config
        """

        of = open("/tmp/facts_l2_interfaces.log","a")
        config = deepcopy(spec)

        of.write ("***\n") ;
        of.write (conf) ;
        of.write ("***\n") ;

        #match = re.search(r"^(\S+)", conf)
        #match = re.search(r"^(\S+)", conf)
        match = re.search(r"^(\S+) (\S+)", conf, re.M|re.I)
        intf = match.group(1)

        of.write("Matchgroup: ")
        of.write(intf)
        of.write("\n")

        if get_interface_type(intf) == "unknown":
            return {}

        if intf.upper()[:2] in (
            "HU",
            "FO",
            "TW",
            "TE",
            "GI",
            "FA",
            "ET",
            "PO",
        ):
            # populate the facts from the configuration

            of.write ("+++\n") 
            of.write (intf) 
            of.write ("+++\n") 

            intf = match.group(1) + " " + match.group(2)

            config["name"] = normalize_interface(intf)
            has_mode = utils.parse_conf_arg(conf, "switchport mode")
            if has_mode:
                config["mode"] = has_mode
            has_access = utils.parse_conf_arg(conf, "switchport pvid")
            if has_access:
                config["access"] = {"vlan": int(has_access)}

            has_voice = utils.parse_conf_arg(conf, "switchport voice vlan")
            if has_voice:
                config["voice"] = {"vlan": int(has_voice)}

            trunk = dict()
            trunk["encapsulation"] = utils.parse_conf_arg(
                conf, "switchport trunk encapsulation"
            )


            native_vlan = parse_conf_arg2(conf, "switchport general allowed vlan", "untagged")
            allowed_vlan =parse_conf_arg2(conf, "switchport general allowed vlan", "tagged")

            if native_vlan:
                trunk["native_vlan"] = int(native_vlan)
            if allowed_vlan:
                trunk["allowed_vlans"] = allowed_vlan.split(",")
            allowed_vlan_add_all = re.findall("allowed vlan add.*", conf)
            if allowed_vlan_add_all:
                for each in allowed_vlan_add_all:
                    trunk["allowed_vlans"].extend(
                        each.split("allowed vlan add ")[1].split(",")
                    )
            pruning_vlan = utils.parse_conf_arg(conf, "pruning vlan")
            if pruning_vlan:
                trunk["pruning_vlans"] = pruning_vlan.split(",")

            config["trunk"] = trunk

        return utils.remove_empties(config)


def parse_conf_arg2(cfg, arg1, arg2):
    """
    Parse config based on argument

    :param cfg: A text string which is a line of configuration.
    :param arg: A text string which is to be matched.
    :rtype: A text string
    :returns: A text string if match is found
    """
    match = re.search(r"%s (.+) %s(\n|$)" % (arg1, arg2), cfg, re.M)
    if match:
        result = match.group(1).strip()
    else:
        result = None
    return result
