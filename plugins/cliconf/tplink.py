#
# (c) 2017 Red Hat Inc.
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
#
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
---
author: Egor Zaitsev (@heuels)
cliconf: tplink
short_description: Use tplink cliconf to run command on Cisco SMB network devices
description:
  - This tplink plugin provides low level abstraction apis for
    sending and receiving CLI commands from Cisco SMB network devices.
'''

import re
import json

from ansible.module_utils._text import to_text
from ansible.plugins.cliconf import CliconfBase, enable_mode
from ansible_collections.ansible.netcommon.plugins.module_utils.network.common.utils import (
    to_list,
)
from ansible.module_utils.common._collections_compat import Mapping



class Cliconf(CliconfBase):

    def get_device_info(self):
        device_info = {}
        device_info['network_os'] = 'tplink'

        resource = self.get('enable')
        resource = self.get('show system-info')
        data = to_text(resource, errors='surrogate_or_strict').strip()
        match = re.search(r"^System Description\s*-\s(.*)$", data, re.M)
        if match:
            device_info['network_os_version'] = match.group(1)
        match = re.search(r"^\sSystem Description\s*-\s(.*)$", data, re.M)
        if match:
            device_info['network_os_version'] = match.group(1)
 
        #model = self.get('show inventory')
        #data = to_text(model, errors='surrogate_or_strict').strip()
        #match = re.search(r'PID: (.+)$', data, re.M)
        #if match:
        #    device_info['network_os_model'] = match.group(1)

        data = to_text(resource, errors='surrogate_or_strict').strip()
        match = re.search(r"^ Model\s*\- (\S+)\s*.*$", data, re.M)
        if match:
            device_info['network_os_model'] = match.group(1)

        data = to_text(resource, errors='surrogate_or_strict').strip()
        match = re.search(r"^ System Name          -\s(.*)$", data, re.M)
        if match:
            device_info['network_os_hostname'] = match.group(1)
        match = re.search(r"^ Device Name          -\s(.*)$", data, re.M)
        if match:
            device_info['network_os_hostname'] = match.group(1)

        return device_info

    def check_device_type(self):
         device_type = "L2"
         try:
             self.get(command="show vlan")
         except Exception:
             device_type = "L3"

         dt = open ("/tmp/dt.log","a")
         dt.write ("Device type is %s\n" % device_type)
         return device_type

    @enable_mode
    def get_config(self, source='running', flags=None, format=None):
        if source not in ("running", "startup"):
            raise ValueError(
                "fetching configuration from %s is not supported" % source
            )

        if format:
            raise ValueError(
                "'format' value %s is not supported for get_config" % format
            )

        if flags:
            raise ValueError(
                "'flags' value %s is not supported for get_config" % flags
            )

        if source == "running":
            cmd = "show running-config "
        else:
            cmd = "show startup-config "

        return self.send_command(cmd)



    @enable_mode
    def edit_config(
        self, candidate=None, commit=True, replace=None, comment=None
    ):
        resp = {}
        operations = self.get_device_operations()
        self.check_edit_config_capability(
            operations, candidate, commit, replace, comment
        )

        results = []
        requests = []

        out = open ("/tmp/edit_config.log", "a")

        if commit:
            out.write("configure\n") 
            #self.send_command("configure")
            for line in to_list(candidate):
                if not isinstance(line, Mapping):
                    line = {"command": line}

                cmd = line["command"]

                out.write (cmd) 
                out.write ('\n')

                if cmd != "end" and cmd[0] != "!":
                    results.append(self.send_command(**line))
                    requests.append(cmd)

            self.send_command("end")
        else:
            raise ValueError("check mode is not supported")

        resp["request"] = requests
        resp["response"] = results

        for res in results:
          out.write (res)
          out.write ("\n")
        return resp

    def get(self, command, prompt=None, answer=None, pgstr=None, sendonly=False, newline=True, check_all=False):

        #prompt="Press any key to continue.*"
        #answer=" "

        of = open("/tmp/tplink-cli.log", "a")
        of.write ("Command  : %s\n" % command)
        of.write ("Prompt   : %s\n" % prompt)
        of.write ("Answer   : %s\n" % answer)
        of.write ("Checkall : %s\n" % check_all)

        #pgstr = '.*Quit.*Next Page.*Next Entry.*All'
        pgstr = 'Press any key to continue.*'


        #of.write ("Pagerstr : %s\n" % pgstr)

        #out = self.send_command(command=command, prompt=prompt, answer=answer, pgstr=pgstr, sendonly=sendonly, newline=newline, check_all=check_all)


        out = self.send_command(command=command, prompt=prompt, answer=answer, sendonly=sendonly, newline=newline, check_all=check_all)
        of.write ("Reponse: %s\n" % out)
        return (out)

    def get_capabilities(self):
        result = super().get_capabilities()
        return json.dumps(result)

    def get_device_operations(self):
        return {
            "supports_diff_replace": True,
            "supports_commit": False,
            "supports_rollback": False,
            "supports_defaults": True,
            "supports_onbox_diff": False,
            "supports_commit_comment": False,
            "supports_multiline_delimiter": True,
            "supports_diff_match": True,
            "supports_diff_ignore_lines": True,
            "supports_generate_diff": True,
            "supports_replace": False,
        }

