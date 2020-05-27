#!/usr/bin/env python

import sys
import ipaddress
import json
import re
import subprocess
import osquery

#import custom python rules
import kill_process

@osquery.register_plugin
class ActiveResponsePlugin(osquery.TablePlugin):
    """
    Plugin to perform action on machine.
    """

    def name(self):
        return "active_response"

    def columns(self):
        """
        :return:
        stdout will return stdout message.
        stderr will return stderr message
        action can be "iptable_rule" or "process_kill"
        arguments are the command line arguments passed from clients.
        """
        return [
            osquery.TableColumn(name="action", type=osquery.STRING),
            osquery.TableColumn(name="arguments", type=osquery.STRING),
            osquery.TableColumn(name="stdout", type=osquery.STRING),
            osquery.TableColumn(name="stderr", type=osquery.STRING),
        ]

    def get_context_list_val(self, val):
        return "" if not val else val[0]["expr"]

    def generate(self, context):
        """
        :param context:
        :return:
        It will parse the context's arguments and will fetch user supplied info to be executed on machine.
        """
        cmd_lines = map(lambda x: (x["name"], self.get_context_list_val(x['list'])),
                        json.loads(json.loads(context))["constraints"])
        row = dict(cmd_lines)
        stdout, stderr = self.process_and_run_cmd(row)
        row['stdout'] = stdout
        row['stderr'] = stderr
        return [row]

    def process_and_run_cmd(self, cmd_dict):
        try:
            return ActiveResponse(cmd_dict).respond()
        except (AttributeError, ValueError, TypeError) as e:
            return "", str(e)

class ActiveResponse(object):
    """
    Entry point of the executeion that will call the required actions.
    Add any new Rule file here. Default is the active response rule files from wazuh-response
    """
    WAZUH_RULES = [
        'route-null.sh',
        'ip-customblock.sh',
        'default-firewall-drop.sh',
        'host-deny.sh',
        'ipfw_mac.sh',
        'npf.sh',
        'ipfw.sh',
        'pf.sh',
        'route-null.cmd',
        'netsh.cmd',
        'disable-account.sh',
        'firewalld-drop.sh',
    ]

    PYTHON_RULE = [
        'kill_process'
    ]

    BASH_RULE = [

    ]

    def __init__(self, cmd_dict):
        self.cmd_dict = cmd_dict
        self.rule = self.cmd_dict["rule"]
        self.action = self.cmd_dict.get("action","-")
        self.user = self.cmd_dict.get("user", "-")
        self.ip = self.cmd_dict.get("ip", "-")
        self.args = self.cmd_dict.get("args","")
        self.validate_arguments()

    def rule_obj(self):
        module = sys.modules.get(self.rule)
        return getattr(module, "Rule")(self.args)

    def validate_arguments(self):
        assert self.ip == "-" or ipaddress.ip_address(self.ip)
        assert self.action in ["-","add","delete"]
        assert re.match("^[a-zA-Z0-9_.-]+$", self.user)
        assert self.rule in ActiveResponse.WAZUH_RULES + ActiveResponse.PYTHON_RULE + ActiveResponse.BASH_RULE
        if self.rule in ActiveResponse.PYTHON_RULE:
            assert self.rule_obj().validate_arguments()

    def build_command(self):
        command = [self.rule,self.action,self.user,self.ip]
        if self.rule in ActiveResponse.PYTHON_RULE:
            command =  self.rule_obj().command()
        elif self.rule.endswith(".cmd"):
            command.insert(0,self.rule)
        else:
            command[0]="./"+self.rule
        return command

    def respond(self):
        command = self.build_command()
        p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        if not out:
            out = "response-executed"
        return [out, err]

if __name__ == "__main__":
    osquery.start_extension(name="active_response_extension", version="1.0.0")
