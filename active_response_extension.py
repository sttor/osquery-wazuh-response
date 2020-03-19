#!/usr/bin/env python

import ipaddress
import json
import subprocess
import osquery
from collections import OrderedDict


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

    def process_and_run_cmd(self, cmd_dict):
        try:
            return ActiveResponse(cmd_dict).respond()
        except (AttributeError, ValueError, TypeError) as e:
            return "", str(e)

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


class ActiveResponse(object):
    """
    Entry point of the executeion that will call the required actions.
    """

    def __init__(self, cmd_dict):
        self.cmd_dict = cmd_dict

    def respond(self):
        stdout, stderr = getattr(ActiveResponse, self.cmd_dict["action"])(self)
        if not stdout:
            stdout = "response-executed"
        return [stdout, stderr]

    def iptable_rule(self):
        rule = IPTableRule(self.cmd_dict)
        return rule.execute_command()

    def process_kill(self):
        rule = ProcessKillRule(self.cmd_dict)
        return rule.execute_command()


class ActiveResponseRule(object):
    """
    Interface class to define functions that the subclass will implement.
    """

    def __init__(self, cmd_dict):
        self.arguments = json.loads(cmd_dict['arguments'])
        self.validation_errors = []

    def execute_command(self):

        if self.validate_arguments():
            try:
                return self.execute_subprocess_command()
            except Exception as e:
                return ["Unexcepted Execution error", str(e)]
        else:
            return ["Arguments error", ",".join(self.validation_errors)]


class ProcessKillRule(ActiveResponseRule):
    """
    This class will help to kill and process, kill -SIGNAL PID
    """

    def execute_subprocess_command(self):
        """
        :return:
        This will execute subprocess command
        """
        command = ["kill", "-" + str(self.arguments["signal"]), str(self.arguments["pid"])]
        p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        return [out, err]

    def validate_arguments(self):
        """
        :return:
        It validates the pid and signal.
        """
        return str(self.arguments["pid"]).isdigit() and 1 <= int(self.arguments["signal"]) <= 62


class IPTableRule(ActiveResponseRule):
    """
    This class mimic IPtable rules with limited command and arguments allowed.
    """

    ALLOWED_IP_TABLE_KEY_VALUE = OrderedDict([
        ("-A", lambda x: x in ["INPUT", "OUTPUT"]),
        ("-D", lambda x: x in ["INPUT", "OUTPUT"]),
        ("-p", lambda x: IPTableRule.is_valid_protocol(x)),
        ("-s", lambda x: IPTableRule.is_valid_ip_range(x)),
        ("-d", lambda x: IPTableRule.is_valid_ip_range(x)),
        ("-m", lambda x: x in ["multiport"]),
        ("--dports", lambda x: IPTableRule.is_valid_port_csv(x)),
        ("--sports", lambda x: IPTableRule.is_valid_port_csv(x)),
        ("-j", lambda x: x in ["ACCEPT", "DROP"])
    ])

    @staticmethod
    def is_valid_ip_range(ip_str):
        """
        :param ip_str:
        :return:
        It validates if the ip string is a valid IPv4 address or IPv4 Address range.
        """
        ip_list = ip_str.split(",")
        for ip_str in ip_list:
            try:
                if not str(ipaddress.IPv4Network(ip_str)) == str(ip_str):
                    ip = ipaddress.IPv4Address(ip_str)
                else:
                    return True
            except (ipaddress.AddressValueError, ipaddress.NetmaskValueError) as e:
                return False
        return True

    @staticmethod
    def is_valid_port_csv(port_str_csv):
        """
        :param port_str_csv:
        :return:
        It validates if port is in valid range or not.
        """
        return len(list(filter(lambda x: not 1 <= int(x) <= 65535, port_str_csv.split(",")))) == 0

    def validate_arguments(self):
        """
        :return:
        This function validate all the arguments received from the cmd_line.
        """
        for key in self.arguments:
            if not IPTableRule.ALLOWED_IP_TABLE_KEY_VALUE[key](self.arguments[key]):
                return False
        return True

    @staticmethod
    def is_valid_protocol(protocol):
        """
        :param protocol:
        :return:
        Validates if protocol is valid or not for iptable.
        """
        return protocol in ["tcp", "udp", "icmp", "all"]

    def execute_subprocess_command(self):
        """
        :return:
        Execute iptable rule on the machine.
        """
        command = ["iptables"]
        for key, _ in IPTableRule.ALLOWED_IP_TABLE_KEY_VALUE.items():
            if key in self.arguments.keys():
                command.extend([key, self.arguments[key]])
        p = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate()
        return [out, err]


if __name__ == "__main__":
    osquery.start_extension(name="active_response_extension", version="1.0.0")
