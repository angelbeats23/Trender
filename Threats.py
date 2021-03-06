#
# Threat Super Class
# @version 1.0
# @author Dexter Griffiths <11074220@brookes.ac.uk>
#
from datetime import datetime, timedelta
import random


class Threat(object):
    def __init__(self, s_ip='any', s_port='any', dst_ip='any', dst_port='any'):
        self._source_ip = s_ip
        self._source_port = s_port
        self._destination_ip = dst_ip
        self._destination_port = dst_port
        self._timestamp = ''
        self._payload = ''
        self._class_name = ''

        self._source_ip_list = []
        self._source_port_list = []
        self._destination_ip_list = []
        self._destination_port_list = []
        self._timestamp_list = []
        self._payload_list = []
        self._class_name_list = []

        # Boolean to indicate an attack has occur or not
        self._attack_identified = False

        # Sets the format for timestamps values in datetime objects
        self.t_format = '%Y-%m-%d %H:%M:%S'

        # stores the snort reject rule
        self._rule_against_attackers = ''

        # Boolean to indicate an attack has occur or not
        self._dangerous_parameter_detected = False

    def check_all_timestamps(self, timestamp_recent, compare_threat_timestamps, min_threat_limit):
        timestamp_counter = 0
        # Is there enough potential threat packets ( minimum number of timestamps allowed)
        if len(self._timestamp_list) > min_threat_limit:
            for count in range(0, len(self._timestamp_list)-1):
                # if the current time minus the potential threat packets timestamp < user specified time
                if (datetime.now() - datetime.strptime(self._timestamp_list[count], self.t_format)) < \
                        timedelta(minutes=timestamp_recent):
                    temp_timestamp = datetime.strptime(self._timestamp_list[count], self.t_format)
                    temp_timestamp1 = datetime.strptime(self._timestamp_list[count+1], self.t_format)
                    # if the current timestamp and next timestamp is < the user specified time
                    if (temp_timestamp1 - temp_timestamp) < timedelta(seconds=compare_threat_timestamps):
                        # add one to the identified intrusion packet counter
                        timestamp_counter += 1
                        # if the number of intrusion is >= user specified number
                        # then create a snort rule for the intrusion
                        if timestamp_counter >= min_threat_limit:
                            self._attack_identified = True
        return self._attack_identified

    def parameter_alias(self, parameter_description):
        # this function assists the delete_duplicate_parameter()
        temp_list = []
        if parameter_description in 's_ip':
            temp_list = self._source_ip_list
        elif parameter_description in 's_port':
            temp_list = self._source_port_list
        elif parameter_description in 'dst_ip':
            temp_list = self._destination_ip_list
        elif parameter_description in 'dst_port':
            temp_list = self._destination_port_list
        return temp_list

    def delete_duplicate_parameter(self, parameter, min_matches):
        # parameter specifies either source ip, source port, destination ip, destination port to search for duplicates
        # in a list.the function removes duplicates in a list. an check if the minimum number of the parameters
        # attribute is still left after deleting duplicates. (is there enough potential intrusion packets)
        duplicate_list = self.parameter_alias(parameter)
        temp_timestamp_list = self._timestamp_list
        for item in duplicate_list:
            temp_timestamp_list.append(self._timestamp_list[duplicate_list.index(item)])
            while duplicate_list.count(item) > 1:
                duplicate_list.remove(item)
                del self._timestamp_list[duplicate_list.index(item)]
        self._timestamp_list = temp_timestamp_list

        if len(temp_timestamp_list) > min_matches:
            self._dangerous_parameter_detected = True
        return self._dangerous_parameter_detected

    def verified_parameters_timestamps(self, parameter, timestamp_recent,
                                             compare_threat_timestamps, threshold):
        timestamp_count = 0
        # delete duplicate potential intrusion packets
        if self.delete_duplicate_parameter(parameter, threshold) is True:
            for count in range(0, len(self._timestamp_list)-1):
                # if the current time minus the potential threat packets timestamp < user specified time
                if (datetime.now() - datetime.strptime(self._timestamp_list[count], self.t_format)) < \
                        timedelta(minutes=timestamp_recent):
                    temp_timestamp_0 = datetime.strptime(self._timestamp_list[count], self.t_format)
                    temp_timestamp_1 = datetime.strptime(self._timestamp_list[count+1], self.t_format)
                    # if the current timestamp and next timestamp is < the user specified time
                    if (temp_timestamp_1 - temp_timestamp_0) < timedelta(seconds=compare_threat_timestamps):
                        # add one to the identified intrusion packet counter
                        timestamp_count += 1
                        # if the number of intrusion is >= user specified number
                        # then create a snort rule for the intrusion
                        if timestamp_count >= threshold:
                            self._dangerous_parameter_detected = True
        return self._dangerous_parameter_detected

    def set_snort_rule_string(self):
        # this function will create the snort rule that will be used to drop the identified threat packets.
        pass

    def get_snort_rule_string(self):
        # this function will create the snort rule that will be used to drop the identified threat packets.
        return self._rule_against_attackers

    def set_source_ip(self, source_ip):
        self._source_ip = source_ip

    def get_source_ip(self):
        return self._source_ip

    def set_source_port(self, source_port):
        self._source_ip = source_port

    def get_source_port(self):
        return self._source_port

    def set_destination_ip(self, destination_ip):
        self._destination_ip = destination_ip

    def get_destination_ip(self):
        return self._destination_ip

    def set_destination_port(self, destination_port):
        self._destination_port = destination_port

    def get_destination_port(self):
        return self._destination_port

    def set_timestamp(self, timestamp):
        self._timestamp = timestamp

    def get_timestamp(self):
        return self._timestamp

    def set_payload(self, payload):
        self._payload = payload

    def get_payload(self):
        return self._payload

    def set_class_name(self, name):
        self._class_name = name

    def get_class_name(self):
        return self._class_name

    def set_source_ip_list(self, source_ip):
        self._source_ip_list.append(source_ip)

    def get_source_ip_list(self, source_ip_location_num):
        return self._source_ip_list[source_ip_location_num]

    def get_source_ip_list_length(self):
        return len(self._source_ip_list)

    def set_source_port_list(self, source_port):
        self._source_port_list.append(source_port)

    def get_source_port_list(self, source_port_location_num):
        return self._source_port_list[source_port_location_num]

    def get_source_port_list_length(self):
        return len(self._source_port_list)

    def set_destination_ip_list(self, destination_ip):
        self._destination_ip_list.append(destination_ip)

    def get_destination_ip_list(self, destination_ip_location_num):
        return self._destination_ip_list[destination_ip_location_num]

    def get_destination_ip__list_length(self):
        return len(self._destination_ip_list)

    def set_destination_port_list(self, destination_port):
        self._destination_port_list.append(destination_port)

    def get_destination_port_list(self, destination_port_location_num):
        return self._destination_port_list[destination_port_location_num]

    def get_destination_port_list_length(self):
        return len(self._destination_port_list)

    def set_timestamp_list(self, timestamp):
        self._timestamp_list.append(timestamp)

    def get_timestamp_list(self, timestamp_location_num):
        return self._timestamp_list[timestamp_location_num]

    def get_timestamp_list_length(self):
        return len(self._timestamp_list)

    def set_payload_list(self, payload):
        self._payload_list.append(payload)

    def get_payload_list(self, payload_location_num):
        return self._payload_list[payload_location_num]

    def get_payload_list_length(self):
        return len(self._payload_list)

    def set_class_name_list(self, name):
        self._class_name_list.append(name)

    def get_class_name_list(self, name_location_num):
        return self._class_name_list[name_location_num]

    def get_class_name_list_length(self):
        return len(self._class_name_list)

    def get_randnum(self):
        # returns a random number for the SID of the snort reject rules
        # else snort service will not execute if there are snort rules with duplicate SID's
        return random.randint(1000, 999999)


class BruteForce(Threat):

    def __init__(self):
        super(BruteForce, self).__init__(dst_port='23')

    def set_snort_rule_string(self):
        # Snort reject rule string variable for BruteForce attacks
        snort_rule = "reject tcp {} {} -> {} {} " \
                     "(msg:\"Telnet BruteForce Permission Denied\"; " \
                     "flow:to_server,established; metadata:ruleset community, service telnet; " \
                     "classtype:suspicious-login; sid:{}; " \
                     "rev:1;)\n".format(self._destination_ip, self._source_port, self._source_ip, self._destination_port, Threat.get_randnum(self))
        self._rule_against_attackers = snort_rule


class PingSweep(Threat):

    def __init__(self):
        super(PingSweep, self).__init__(dst_port='any')

    def set_snort_rule_string(self):
        # Snort reject rule string variable for PingSweep attacks
        snort_rule = "reject icmp {} {} -> {} {} (msg:\"PingSweep Reconnaissance Attack\"; " \
                     "classtype:successful-recon-largescale; sid:{}; " \
                     "rev:1;)\n".format(self._source_ip, self._source_port, self._destination_ip, self._destination_port, Threat.get_randnum(self))
        self._rule_against_attackers = snort_rule


class SynFlood(Threat):

    def __init__(self):
        super(SynFlood, self).__init__(dst_port='80')

    def set_snort_rule_string(self):
        # Snort reject rule string variable for SYN Flood attacks
        snort_rule = "reject tcp {} {} -> {} {} (msg:\"Syn Flood Attack\"; flow:stateless; flags:S; " \
                     "classtype:successful-dos; sid:{}; " \
                     "rev:1;)\n".format(self._source_ip, self._source_port, self._destination_ip, self._destination_port, Threat.get_randnum(self))
        self._rule_against_attackers = snort_rule

