from datetime import datetime, timedelta


class SynFlood:

    def __init__(self):
        self._source_ip = ''
        self._destination_ip = ''
        self._destination_port = ''
        self._timestamp = []
        self._attack_identified = False
        self.t_format = '%Y-%m-%d %H:%M:%S'
        self._rule_against_attackers = ''
        self._rule_against_attackers_random_sip = ''
        self._random_source_ip_list = []
        self._rand_source_ips_detected = False

    def set_source_ip(self, source_ip):
        self._source_ip = source_ip

    def get_source_ip(self):
        return self._source_ip

    def set_destination_ip(self, destination_ip):
        self._destination_ip = destination_ip

    def get_destination_ip(self):
        return self._destination_ip

    def set_destination_port(self, destination_port):
        self._destination_port = destination_port

    def get_destination_port(self):
        return self._destination_port

    def set_timestamp(self, timestamp):
        self._timestamp.append(timestamp)

    def get_timestamp(self, timestamp_location_num):
        return self._timestamp[timestamp_location_num]

    def set_random_source_ip_list(self, random_source_ip_list):
        self._random_source_ip_list.append(random_source_ip_list)

    def check_all_timestamps(self):
        timestamp_counter = 0
        if len(self._timestamp) > 10:
            for count in range(0, len(self._timestamp)-1):
                if (datetime.now() - datetime.strptime(self._timestamp[count], self.t_format)) < timedelta(minutes=20):
                    temp_timestamp = datetime.strptime(self._timestamp[count], self.t_format)
                    temp_timestamp1 = datetime.strptime(self._timestamp[count+1], self.t_format)
                    if (temp_timestamp1 - temp_timestamp) < timedelta(seconds=2):
                        timestamp_counter += 1
                        if timestamp_counter > 10:
                            self._attack_identified = True
        return self._attack_identified

    def get_snort_rule_string(self):
        self._rule_against_attackers = "drop tcp {} any -> {} {} (msg:\"Syn Flood Attack\"; flow:stateless flags:S; classtype:successful-dos; sid:1000004; rev:1;)\n".format(self._source_ip, self._destination_ip, self._destination_port)
        return self._rule_against_attackers

    def check_timestamps_random_sip(self):
        timestamp_counter = 0
        if self.check_rand_source_ip() is True:
            for count in range(0, len(self._timestamp)-1):
                if (datetime.now() - datetime.strptime(self._timestamp[count], self.t_format)) < timedelta(minutes=20):
                    temp_timestamp = datetime.strptime(self._timestamp[count], self.t_format)
                    temp_timestamp1 = datetime.strptime(self._timestamp[count+1], self.t_format)
                    if (temp_timestamp1 - temp_timestamp) < timedelta(seconds=2):
                        timestamp_counter += 1
                        if timestamp_counter > 10:
                            self._attack_identified = True
        return self._attack_identified

    def check_rand_source_ip(self):
        count = 0
        temp_sip_list = []
        for item in self._random_source_ip_list:
            if item in temp_sip_list:
                del self._timestamp[count]
            else:
                temp_sip_list.append(item)
            count += 1
        if len(temp_sip_list) > 10:
            self._rand_source_ips_detected = True
        return self._rand_source_ips_detected

    def get_snort_rule_string_random_sip(self):
        self._rule_against_attackers_random_sip = "drop tcp any any -> {} {} (msg:\"Syn Flood Attack\"; flow:stateless flags:S; classtype:successful-dos; sid:1000004; rev:1;)\n".format(self._destination_ip, self._destination_port)
        return self._rule_against_attackers_random_sip

    def empty_object(self):
        self._source_ip = ''
        self._destination_ip = ''
        self._destination_port = ''
        self._timestamp = []
        self._attack_identified = False
        self._rule_against_attackers = ''
        self._rule_against_attackers_random_sip = ''
        self._random_source_ip_list = []
        self._rand_source_ips_detected = False