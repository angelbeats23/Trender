
class PacketDB:

    def __init__(self):
        self._source_ip = []
        self._source_port = []
        self._destination_ip = []
        self._destination_port = []
        self._timestamp = []
        self._payload = []
        self._class_name_data = []
        self.icmp_packet_data = []
        self._telnet_packet_data = []
        self._class_name = []

        self._source_ip_list = []
        self._source_port_list = []
        self._destination_ip_list = []
        self._destination_port_list = []
        self._timestamp_list = []
        self._payload_list = []
        self._class_name_list = []

    def get_sorted_syn_source_ip_list(self):
        del self._class_name_data[:]
        for item in self._source_ip:
            if item in self._class_name_data:
                pass
            else:
                self._class_name_data.append(item)
        return self._class_name_data

    def get_sorted_syn_destination_ip_list(self):
        del self._class_name_data[:]
        for item in self._destination_ip:
            if item in self._class_name_data:
                pass
            else:
                self._class_name_data.append(item)
        return self._class_name_data

    def get_sorted_syn_destination_port_list(self):
        del self._class_name_data[:]
        for item in self._destination_port:
            if item in self._class_name_data:
                pass
            else:
                self._class_name_data.append(item)
        return self._class_name_data

    def get_syn_flood_source_ip(self):
        count = 0
        del self._class_name_data[:]
        for item in self._class_name:
            if 'attempted-dos' in item:
                self._class_name_data.append(self._source_ip[count])
            count += 1
        return self._class_name_data

    def get_syn_flood_destination_ip(self):
        count = 0
        del self._class_name_data[:]
        for item in self._class_name:
            if 'attempted-dos' in item:
                self._class_name_data.append(self._destination_ip[count])
            count += 1
        return self._class_name_data

    def get_syn_flood_destination_port(self):
        count = 0
        del self._class_name_data[:]
        for item in self._class_name:
            if 'attempted-dos' in item:
                self._class_name_data.append(self._destination_port[count])
            count += 1
        return self._class_name_data

    def get_syn_flood_timestamp(self):
        count = 0
        del self._class_name_data[:]
        for item in self._class_name:
            if 'attempted-dos' in item:
                self._class_name_data.append(self._timestamp[count])
            count += 1
        return self._class_name_data

    def get_sorted_icmp_source_ip_list(self):
        del self.icmp_packet_data[:]
        for item in self._source_ip:
            if item in self.icmp_packet_data:
                pass
            else:
                self.icmp_packet_data.append(item)
        return self.icmp_packet_data

    def get_icmp_source_ip(self):
        count = 0
        del self.icmp_packet_data[:]
        for item in self._destination_port:
            if item is None:
                self.icmp_packet_data.append(self._source_ip[count])
            count += 1
        return self.icmp_packet_data

    def get_icmp_destination_ip(self):
        count = 0
        del self.icmp_packet_data[:]
        for item in self._destination_port:
            if item is None:
                self.icmp_packet_data.append(self._destination_ip[count])
            count += 1
        return self.icmp_packet_data

    def get_icmp_timestamp(self):
        count = 0
        del self.icmp_packet_data[:]
        for item in self._destination_port:
            if item is None:
                self.icmp_packet_data.append(self._timestamp[count])
            count += 1
        return self.icmp_packet_data

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
        elif parameter_description in 'timestamp':
            temp_list = self._timestamp_list = []
        elif parameter_description in 'payload':
            temp_list = self._payload_list = []
        elif parameter_description in 'cl_name':
            temp_list = self._class_name_list = []
        return temp_list

    def get_unique_parameter_list(self, packet_param):
        temp_list = self.parameter_alias(packet_param)
        unique_packet_db = []
        for item in temp_list:
            if item in unique_packet_db:
                pass
            else:
                unique_packet_db.append(item)
        return unique_packet_db

    def get_protocol_lists(self, search_param, required_item, packet_param):
        search_list = self.parameter_alias(search_param)
        unique_packet_list = []
        packet_list = self.parameter_alias(packet_param)
        count = 0
        for item in search_list:
            if item is required_item:
                unique_packet_list.append(packet_list[count])
            count += 1
        return unique_packet_list

    def get_sorted_telnet_source_ip_list(self):
        del self._telnet_packet_data[:]
        for item in self._source_ip:
            if item in self._telnet_packet_data:
                pass
            else:
                self._telnet_packet_data.append(item)
        return self._telnet_packet_data

    def get_sorted_telnet_destination_ip_list(self):
        del self._telnet_packet_data[:]
        for item in self._destination_ip:
            if item in self._telnet_packet_data:
                pass
            else:
                self._telnet_packet_data.append(item)
        return self._telnet_packet_data

    def get_telnet_source_ip(self):
        count = 0
        del self._telnet_packet_data[:]
        for item in self._source_port:
            if item is not None:
                if int(item) is 23:
                    self._telnet_packet_data.append(self._source_ip[count])
            count += 1
        return self._telnet_packet_data

    def get_telnet_destination_ip(self):
        count = 0
        del self._telnet_packet_data[:]
        for item in self._source_port:
            if item is not None:
                if int(item) is 23:
                    self._telnet_packet_data.append(self._destination_ip[count])
            count += 1
        return self._telnet_packet_data

    def get_telnet_timestamp(self):
        count = 0
        del self._telnet_packet_data[:]
        for item in self._source_port:
            if item is not None:
                if int(item) is 23:
                    self._telnet_packet_data.append(self._timestamp[count])
            count += 1
        return self._telnet_packet_data

    def set_source_ip(self, source_ip):
        self._source_ip.append(source_ip)

    def get_source_ip(self, source_ip_location_num):
        return self._source_ip[source_ip_location_num]

    def get_source_ip_length(self):
        return len(self._source_ip)

    def set_source_port(self, source_port):
        self._source_port.append(source_port)

    def get_source_port(self, source_port_location_num):
        return self._source_port[source_port_location_num]

    def get_source_port_length(self):
        return len(self._source_port)

    def set_destination_ip(self, destination_ip):
        self._destination_ip.append(destination_ip)

    def get_destination_ip(self, destination_ip_location_num):
        return self._destination_ip[destination_ip_location_num]

    def get_destination_ip_length(self):
        return len(self._destination_ip)

    def set_destination_port(self, destination_port):
        self._destination_port.append(destination_port)

    def get_destination_port(self, destination_port_location_num):
        return self._destination_port[destination_port_location_num]

    def get_destination_port_length(self):
        return len(self._destination_port)

    def set_timestamp(self, timestamp):
        self._timestamp.append(timestamp)

    def get_timestamp(self, timestamp_location_num):
        return self._timestamp[timestamp_location_num]

    def get_timestamp_length(self):
        return len(self._timestamp)

    def set_payload(self, payload):
        self._payload.append(payload)

    def get_payload(self, payload_location_num):
        return self._payload[payload_location_num]

    def set_class_name(self, name):
        self._class_name.append(name)

    def get_class_name(self, name_location_num):
        return self._class_name[name_location_num]

    def get_class_name_length(self):
        return len(self._class_name)
