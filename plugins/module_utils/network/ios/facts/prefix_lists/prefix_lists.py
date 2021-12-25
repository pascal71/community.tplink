# -*- coding: utf-8 -*-
# Copyright 2021 Red Hat
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

"""
The community.tplink prefix_lists fact class
It is in this file the configuration is collected from the device
for a given resource, parsed, and the facts tree is populated
based on the configuration.
"""

from copy import copy

from ansible.module_utils.six import iteritems
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common import (
    utils,
)
from ansible_collections.community.tplink.plugins.module_utils.network.ios.rm_templates.prefix_lists import (
    Prefix_listsTemplate,
)
from ansible_collections.community.tplink.plugins.module_utils.network.ios.argspec.prefix_lists.prefix_lists import (
    Prefix_listsArgs,
)


class Prefix_listsFacts(object):
    """ The community.tplink prefix_lists facts class
    """

    def __init__(self, module, subspec="config", options="options"):
        self._module = module
        self.argument_spec = Prefix_listsArgs.argument_spec

    def get_prefix_list_data(self, connection):
        return connection.get(
            "sh running-config | section ^ip prefix-list|^ipv6 prefix-list"
        )

    def populate_facts(self, connection, ansible_facts, data=None):
        """ Populate the facts for Prefix_lists network resource

        :param connection: the device connection
        :param ansible_facts: Facts dictionary
        :param data: previously collected conf

        :rtype: dictionary
        :returns: facts
        """
        facts = {}
        objs = []

        if not data:
            data = self.get_prefix_list_data(connection)

        # parse native config using the Prefix_lists template
        prefix_lists_parser = Prefix_listsTemplate(lines=data.splitlines())
        objs = prefix_lists_parser.parse()

        final_objs = []
        temp = {}
        temp["afi"] = None
        temp["prefix_lists"] = []
        if objs:
            for k, v in iteritems(objs):
                temp_prefix_list = {}
                temp_prefix_list["entries"] = []
                if not temp["afi"] or v["afi"] != temp["afi"]:
                    if temp and temp["afi"]:
                        temp["prefix_lists"] = sorted(
                            temp["prefix_lists"],
                            key=lambda k, sk="name": str(k[sk]),
                        )
                        # additional check for py3.5
                        if len(final_objs) == 2:
                            for each in final_objs:
                                if v["afi"] == each["afi"]:
                                    each["prefix_lists"].extend(
                                        temp["prefix_lists"]
                                    )
                        else:
                            final_objs.append(copy(temp))
                            temp["prefix_lists"] = []
                    temp["afi"] = v["afi"]
                for each in v["prefix_lists"]:
                    if not temp_prefix_list.get("name"):
                        temp_prefix_list["name"] = each["name"]
                    if not temp_prefix_list.get("description") and each.get(
                        "description"
                    ):
                        temp_prefix_list["description"] = each["description"]
                    if each["entries"] and not each["entries"].get(
                        "description"
                    ):
                        temp_prefix_list["entries"].append(each["entries"])
                temp["prefix_lists"].append(temp_prefix_list)
            if temp and temp["afi"]:
                temp["prefix_lists"] = sorted(
                    temp["prefix_lists"], key=lambda k, sk="name": str(k[sk])
                )
                # additional check for py3.5
                if len(final_objs) == 2:
                    for each in final_objs:
                        if v["afi"] == each["afi"]:
                            each["prefix_lists"].extend(temp["prefix_lists"])
                else:
                    final_objs.append(copy(temp))

            final_objs = sorted(final_objs, key=lambda k, sk="afi": k[sk])

            ansible_facts["ansible_network_resources"].pop(
                "prefix_lists", None
            )

            params = utils.remove_empties(
                utils.validate_config(
                    self.argument_spec, {"config": final_objs}
                )
            )

            facts["prefix_lists"] = params["config"]
            ansible_facts["ansible_network_resources"].update(facts)

        return ansible_facts
