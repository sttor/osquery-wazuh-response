import json

class Rule(object):
    def __init__(self,arguments):
        self.arguments = json.loads(arguments)

    def command(self):
        return ["kill","-"+str(self.arguments["signal"]),str(self.arguments["pid"])]

    def validate_arguments(self):
        """
        :return:
        It validates the pid and signal.
        """
        return str(self.arguments["pid"]).isdigit() and 1 <= int(self.arguments["signal"]) <= 62
