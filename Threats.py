from datetime import datetime, timedelta


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

        self._attack_identified = False
        self.t_format = '%Y-%m-%d %H:%M:%S'

        self._rule_against_attackers = ''

        self._dangerous_parameter_detected = False

    def check_all_timestamps(self, timestamp_recent, compare_threat_timestamps, min_threat_limit):
        timestamp_counter = 0
        if len(self._timestamp_list) > min_threat_limit:
            for count in range(0, len(self._timestamp_list)-1):
                if (datetime.now() - datetime.strptime(self._timestamp_list[count], self.t_format)) < \
                        timedelta(minutes=timestamp_recent):
                    temp_timestamp = datetime.strptime(self._timestamp_list[count], self.t_format)
                    temp_timestamp1 = datetime.strptime(self._timestamp_list[count+1], self.t_format)
                    if (temp_timestamp1 - temp_timestamp) < timedelta(seconds=compare_threat_timestamps):
                        timestamp_counter += 1
                        if timestamp_counter >= min_threat_limit:
                            self._attack_identified = True
        return self._attack_identified

    def parameter_alias(self, parameter_description):
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
        # in a list.the function removes duplicates in a list. an check if the minumin number of the parameters
        # attribute is still left after deleting duplicates. (is there enough packets left to check timestamps against)
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
        if self.delete_duplicate_parameter(parameter, threshold) is True:
            for count in range(0, len(self._timestamp_list)-1):
                if (datetime.now() - datetime.strptime(self._timestamp_list[count], self.t_format)) < \
                        timedelta(minutes=timestamp_recent):
                    temp_timestamp_0 = datetime.strptime(self._timestamp_list[count], self.t_format)
                    temp_timestamp_1 = datetime.strptime(self._timestamp_list[count+1], self.t_format)
                    if (temp_timestamp_1 - temp_timestamp_0) < timedelta(seconds=compare_threat_timestamps):
                        timestamp_count += 1
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


class BruteForce(Threat):

    def __init__(self):
        super(BruteForce, self).__init__(dst_port='23')

    def set_snort_rule_string(self):
        snort_rule = "drop tcp {} {} -> {} {} " \
                     "(msg:\"Telnet BruteForce Permission Denied\"; " \
                     "flow:to_server,established; metadata:ruleset community, service telnet; " \
                     "classtype:suspicious-login; sid:1000006; " \
                     "rev:1;)".format(self._destination_ip, self._source_port, self._source_ip, self._destination_port)
        self._rule_against_attackers = snort_rule


class PingSweep(Threat):

    def __init__(self):
        super(PingSweep, self).__init__(dst_port='icmp')

    def set_snort_rule_string(self):
        snort_rule = "drop icmp {} {} -> {} {} (msg:\"PingSweep Reconnaissance Attack\"; " \
                     "classtype:successful-recon-largescale; sid:1000003; " \
                     "rev:1;)\n".format(self._source_ip, self._source_port, self._destination_ip, self._destination_port)
        self._rule_against_attackers = snort_rule


class SynFlood(Threat):

    def __init__(self):
        super(SynFlood, self).__init__()

    def set_snort_rule_string(self):
        snort_rule = "drop tcp {} {} -> {} {} (msg:\"Syn Flood Attack\"; flow:stateless flags:S; " \
                     "classtype:successful-dos; sid:1000004; " \
                     "rev:1;)\n".format(self._source_ip, self._source_port, self._destination_ip, self._destination_port)
        self._rule_against_attackers = snort_rule

