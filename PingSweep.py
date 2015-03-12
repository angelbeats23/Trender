from datetime import datetime, timedelta


class PingSweep:

    def __init__(self):
        self._source_ip = ''
        self._destination_ip = []
        self._timestamp = []
        self._destination_ip_detected = False
        self._dangerous_source_ip_detected = False
        self.t_format = '%Y-%m-%d %H:%M:%S'
        self._rules_against_attackers = ""

    def set_source_ip(self, source_ip):
        self._source_ip = source_ip

    def get_source_ip(self):
        return self._source_ip

    def set_destination_ip(self, destination_ip):
        self._destination_ip.append(destination_ip)

    def get_destination_ip(self, destination_ip_location_num):
        return self._destination_ip[destination_ip_location_num]

    def set_timestamp(self, timestamp):
        self._timestamp.append(timestamp)

    def get_timestamp(self, timestamp_location_num):
        return self._timestamp[timestamp_location_num]

    def get_snort_rule_string(self):
        self._rules_against_attackers = "drop icmp {} any -> any icmp (msg:\"PingSweep Reconnaissance Attack\"; " \
                                        "classtype:successful-recon-largescale; " \
                                        "sid:1000003; rev:1;)\n".format(self._source_ip)
        return self._rules_against_attackers

    def check_all_timestamps(self):
        victim_ip_address_count = 0
        if self.check_destination_ip() is True:
            for count in range(0, len(self._timestamp)-1):
                if (datetime.now() - datetime.strptime(self._timestamp[count], self.t_format)) < timedelta(minutes=10):
                    temp_timestamp_0 = datetime.strptime(self._timestamp[count], self.t_format)
                    temp_timestamp_1 = datetime.strptime(self._timestamp[count+1], self.t_format)
                    if (temp_timestamp_1 - temp_timestamp_0) < timedelta(seconds=30):
                        victim_ip_address_count += 1
                        if victim_ip_address_count >= 1:
                            self._dangerous_source_ip_detected = True
        return self._dangerous_source_ip_detected

    def check_destination_ip(self):
        count = 0
        temp_dip_list = []
        for item in self._destination_ip:
            if item in temp_dip_list:
                del self._timestamp[count]
            else:
                temp_dip_list.append(item)
            count += 1
        if len(temp_dip_list) > 1:
            self._dangerous_source_ip_detected = True
        return self._dangerous_source_ip_detected

    def empty_object(self):
        self._source_ip = ''
        self._destination_ip = []
        self._timestamp = []
        self._destination_ip_detected = False
        self._dangerous_source_ip_detected = False
        self._rules_against_attackers = ""