from datetime import datetime, timedelta


class BruteForce:

    def __init__(self):
        self._source_ip = ''
        self._destination_ip = ''
        self._timestamp = []
        self._attack_identified = False
        self.t_format = '%Y-%m-%d %H:%M:%S'
        self._rule_against_attackers = ''

    def set_source_ip(self, source_ip):
        self._source_ip = source_ip

    def get_source_ip(self):
        return self._source_ip

    def set_destination_ip(self, destination_ip):
        self._destination_ip = destination_ip

    def get_destination_ip(self):
        return self._destination_ip

    def set_timestamp(self, timestamp):
        self._timestamp.append(timestamp)

    def get_timestamp(self, timestamp_location_num):
        return self._timestamp[timestamp_location_num]

    def check_all_timestamps(self):
        timestamp_counter = 0
        if len(self._timestamp) > 10:
            for count in range(0, len(self._timestamp)-1):
                if (datetime.now() - datetime.strptime(self._timestamp[count], self.t_format)) < timedelta(minutes=20):
                    temp_timestamp = datetime.strptime(self._timestamp[count], self.t_format)
                    temp_timestamp1 = datetime.strptime(self._timestamp[count+1], self.t_format)
                    if (temp_timestamp1 - temp_timestamp) < timedelta(seconds=40):
                        timestamp_counter += 1
                        if timestamp_counter > 10:
                            self._attack_identified = True
        return self._attack_identified

    def get_snort_rule_string(self):
        self._rule_against_attackers = "drop tcp {} any -> {} 23 " \
                                       "(msg:\"Telnet BruteForce Permission Denied\"; " \
                                       "flow:to_server,established; metadata:ruleset community, service telnet; " \
                                       "classtype:suspicious-login; sid:1000006; " \
                                       "rev:1;)".format(self._destination_ip, self._source_ip)
        return self._rule_against_attackers

    def empty_object(self):
        self._source_ip = ''
        self._destination_ip = ''
        self._timestamp = []
        self._attack_identified = False
        self._rule_against_attackers = ''
