from datetime import datetime, timedelta
import random


class PingSweep:

    def __init__(self):
        self._source_ip = ''
        self._destination_ip = []
        self._timestamp = []
        self._destination_ip_detected = False
        self._additional_dip_packets = []
        self._temp_destination_ip_list = []
        self._dangerous_source_ip = False
        self._victim_ip_address_count = 0
        self.t_format = '%Y-%m-%d %H:%M:%S'
        self._random_sid = random.randrange(1000000, 1999999)
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

    def get_additional_dip_packets(self):
        return self._additional_dip_packets

    def get_snort_rule_string(self):
        self._rules_against_attackers = "drop icmp {} any -> any icmp (msg:\"PingSweep Reconnaissance Attack\"; classtype:successful-recon-largescale; sid:{}; rev:1;)\n".format(self._source_ip, self._random_sid)
        return self._rules_against_attackers

    def get_additional_dip_packets_length(self):
        return len(self._additional_dip_packets)

    def get_destination_ip_pingsweep_check(self):
        count = 0
        for item in self._destination_ip:
            if (datetime.now() - datetime.strptime(self._timestamp[count], self.t_format)) < timedelta(minutes=20):
                print 'timestamp is less than 20 ago'
                if item not in self._temp_destination_ip_list:
                    self._destination_ip_detected = True
                    self._temp_destination_ip_list.append(item)
                    print item
                    self._additional_dip_packets.append(count)
            count += 1
        del self._temp_destination_ip_list[:]
        return self._destination_ip_detected

    def time_differences_between_packets(self):
        count = 0
        for packets in self._additional_dip_packets:
            _temp_timestamp = datetime.strptime(self._timestamp[count], self.t_format)
            _temp_timestamp_2 = datetime.strptime(self._timestamp[self._additional_dip_packets[count]], self.t_format)
            if self._additional_dip_packets.index(packets) is not len(self._additional_dip_packets):
                if (_temp_timestamp_2 - _temp_timestamp) < timedelta(minutes=5):
                    print 'victim ip address confirmed'
                    self._victim_ip_address_count += 1
            count += 1
        if self._victim_ip_address_count > 1:
            self._dangerous_source_ip = True
        return self._dangerous_source_ip

    def empty_pingsweep_object(self):
        self._source_ip = ''
        self._destination_ip = []
        self._timestamp = []
        self._destination_ip_detected = False
        self._additional_dip_packets = []
        self._temp_destination_ip_list = []
        self._dangerous_source_ip = False
        self._victim_ip_address_count = 0
        self._rules_against_attackers = ""