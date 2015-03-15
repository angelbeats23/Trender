import threading
import MySQLdb
import sys
import time
from subprocess import call
from PacketDB import PacketDB
# from PingSweep import PingSweep
# from SynFlood import SynFlood
# from BruteForce import BruteForce
from Threats import *

db = MySQLdb.connect(host="localhost", user="snort", passwd="123456", db="snort")
current_alert_db = PacketDB()
icmp_packet_db = PacketDB()
syn_packet_db = PacketDB()
telnet_packet_db = PacketDB()


class Controller(threading.Thread):
    def __init__(self):
        self._stop_flag = threading.Event()
        self.flag_stop_thread = False
        self.flag_file_accessed = False
        self.snort_cmd = "%s %s %s %s" % ('sudo', 'service', 'snort', 'restart')
        super(Controller, self).__init__()

    # while thread running
    def run(self):
        while not self._stop_flag.is_set():
            # business
            self.flag_stop_thread = False
            self.create_databases()
            self.mysql_database_retrieval()
            self.create_icmp_packet_db()
            self.create_syn_packet_db()
            self.create_telnet_packet_db()
            self.check_for_pingsweep_attacks()
            self.check_for_syn_flood_attacks()
            # self.check_for_syn_flood_attacks_with_random_sip()
            self.check_brute_force_attacks()
            self.restart_snort(self.flag_file_accessed)
            self.clean_up()
            self.flag_stop_thread = True
            time.sleep(10)

    def status(self):
        if not self._stop_flag.is_set():
            print("database is being written")
        else:
            print("thread is stopped")

    def get_flag(self):
        return self.flag_stop_thread

    def restart_snort(self, file_accessed):
        if file_accessed is True:
            call(self.snort_cmd, shell=True)

    def mysql_database_retrieval(self):
        try:
            cursor = db.cursor()
            cursor.execute("USE snort; ")
            cursor.execute("SELECT sig_name FROM acid_event; ")
            for row in cursor.fetchall():
                current_alert_db.set_packet_id(row[0])
            cursor.execute("SELECT acid_ip_cache.ipc_fqdn FROM acid_event,acid_ip_cache WHERE "
                           "acid_event.ip_src = acid_ip_cache.ipc_ip ORDER BY acid_event.cid; ")
            for row in cursor.fetchall():
                current_alert_db.set_source_ip(row[0])
            cursor.execute("SELECT layer4_sport FROM acid_event; ")
            for row in cursor.fetchall():
                current_alert_db.set_source_port(row[0])
            cursor.execute("SELECT acid_ip_cache.ipc_fqdn FROM acid_event,acid_ip_cache WHERE "
                           "acid_event.ip_dst = acid_ip_cache.ipc_ip ORDER BY acid_event.cid; ")
            for row in cursor.fetchall():
                current_alert_db.set_destination_ip(row[0])
                # there is an issue with barnyard storing destination ip addresses in mysql
                # primarily due to the fact that it only stores cached fqdn that have been
                # queried. the only way to do this is by login into base and clicking on every
                # packets destination ip address link which will make it perform a dns lookup.
            cursor.execute("SELECT layer4_dport FROM acid_event; ")
            for row in cursor.fetchall():
                current_alert_db.set_destination_port(row[0])
            cursor.execute("SELECT timestamp FROM acid_event; ")
            for row in cursor.fetchall():
                current_alert_db.set_timestamp(row[0])
            cursor.execute("SELECT sig_class.sig_class_name FROM acid_event,sig_class WHERE "
                           "acid_event.sig_class_id = sig_class.sig_class_id;")
            for row in cursor.fetchall():
                current_alert_db.set_class_name(str(row[0]))

        except MySQLdb.Error, e:
            print "Error %d: %s" % (e.args[0], e.args[1])
            sys.exit(1)

        finally:
            if cursor is not None:
                cursor.close()

    # identify all syn packets and store them in a object
    def create_syn_packet_db(self):
        for sip in current_alert_db.get_syn_flood_source_ip():
            syn_packet_db.set_source_ip(sip)
        for dip in current_alert_db.get_syn_flood_destination_ip():
            syn_packet_db.set_destination_ip(dip)
        for d_port in current_alert_db.get_syn_flood_destination_port():
            syn_packet_db.set_destination_port(d_port)
        for tp in current_alert_db.get_syn_flood_timestamp():
            syn_packet_db.set_timestamp(str(tp))

    def check_for_syn_flood_attacks(self):
        # identifies every packet that matches every possible packet from the unsorted syn_packet_db
        for sip_item in syn_packet_db.get_sorted_syn_source_ip_list():
            for dip_item in syn_packet_db.get_sorted_syn_destination_ip_list():
                for dport_item in syn_packet_db.get_sorted_syn_destination_port_list():
                    # for sip_item, dip_item, dport_item in zip(syn_packet_db.get_sorted_syn_source_ip_list(), \
                    # syn_packet_db.get_sorted_syn_destination_ip_list(), \
                    # syn_packet_db.get_sorted_syn_destination_port_list()):
                    syn_flood_db = SynFlood()
                    syn_flood_db.set_source_ip(sip_item)
                    syn_flood_db.set_destination_ip(dip_item)
                    syn_flood_db.set_destination_port(dport_item)
                    # searches for every packets timestamp that matches all previous criteria
                    for packet in range(0, syn_packet_db.get_timestamp_length()):
                        if sip_item in syn_packet_db.get_source_ip(packet):
                            if dip_item in syn_packet_db.get_destination_ip(packet):
                                if int(dport_item) is int(syn_packet_db.get_destination_port(packet)):
                                    syn_flood_db.set_timestamp(syn_packet_db.get_timestamp(packet))
                    if syn_flood_db.check_all_timestamps(20, 2, 10) is True:
                        self.write_rules_to_file(syn_flood_db.get_snort_rule_string())
                    del syn_flood_db

    # def check_for_syn_flood_attacks_with_random_sip(self):
    #     syn_flood_db2 = SynFlood()
    #     # identifies every packet that matches every possible packet from the unsorted syn_packet_db
    #     for dip_item in syn_packet_db.get_sorted_syn_destination_ip_list():
    #         for dport_item in syn_packet_db.get_sorted_syn_destination_port_list():
    #             syn_flood_db2.set_destination_ip(dip_item)
    #             syn_flood_db2.set_destination_port(dport_item)
    #             # searches for every packets timestamp that matches all previous criteria
    #             for packet in range(0, syn_packet_db.get_timestamp_length()):
    #                     if dip_item in syn_packet_db.get_destination_ip(packet):
    #                         if int(dport_item) is int(syn_packet_db.get_destination_port(packet)):
    #                             syn_flood_db2.set_random_source_ip_list(syn_packet_db.get_source_ip(packet))
    #                             syn_flood_db2.set_timestamp(syn_packet_db.get_timestamp(packet))
    #             if syn_flood_db2.check_timestamps_random_sip() is True:
    #                 self.write_rules_to_file(syn_flood_db2.get_snort_rule_string_random_sip())
    #             syn_flood_db2.empty_object()

    def create_icmp_packet_db(self):
        for sip in current_alert_db.get_icmp_source_ip():
            icmp_packet_db.set_source_ip(sip)
        for dip in current_alert_db.get_icmp_destination_ip():
            icmp_packet_db.set_destination_ip(dip)
        for tp in current_alert_db.get_icmp_timestamp():
            icmp_packet_db.set_timestamp(str(tp))

    def check_for_pingsweep_attacks(self):
        # go through every possible source ip address
        for sip_item in icmp_packet_db.get_sorted_icmp_source_ip_list():
            ping_sweep_db = PingSweep()
            ping_sweep_db.set_source_ip(sip_item)
            # if icmp packet has source ip address add its destination and timestamp
            for packet in range(0, icmp_packet_db.get_source_ip_length()):
                if sip_item in icmp_packet_db.get_source_ip(packet):
                    ping_sweep_db.set_destination_ip(icmp_packet_db.get_destination_ip(packet))
                    ping_sweep_db.set_timestamp(icmp_packet_db.get_timestamp(packet))
            if ping_sweep_db.verified_parameters_timestamps('dst_ip', 10, 30, 1) is True:
                self.write_rules_to_file(ping_sweep_db.get_snort_rule_string())
            del ping_sweep_db

    def create_telnet_packet_db(self):
        for sip in current_alert_db.get_telnet_source_ip():
            telnet_packet_db.set_source_ip(sip)
        for dip in current_alert_db.get_telnet_destination_ip():
            telnet_packet_db.set_destination_ip(dip)
        for tp in current_alert_db.get_telnet_timestamp():
            telnet_packet_db.set_timestamp(str(tp))

    def check_brute_force_attacks(self):
        brute_force_db = BruteForce()
        # go through every possible source ip address
        for sip_item in syn_packet_db.get_sorted_syn_source_ip_list():
            for dip_item in telnet_packet_db.get_sorted_telnet_destination_ip_list():
                brute_force_db.set_source_ip(sip_item)
                brute_force_db.set_destination_ip(dip_item)
                # if icmp packet has source ip address add its destination and timestamp
                for packet in range(0, telnet_packet_db.get_source_ip_length()):
                    if sip_item in telnet_packet_db.get_source_ip(packet):
                        if dip_item in telnet_packet_db.get_destination_ip(packet):
                            brute_force_db.set_timestamp(telnet_packet_db.get_timestamp(packet))
                if brute_force_db.check_all_timestamps(20, 40, 10) is True:
                    self.write_rules_to_file(brute_force_db.get_snort_rule_string())
                del brute_force_db

    def write_rules_to_file(self, string_rule):
        snort_rule_file_list = []
        # change the group and user permission for the file to local user. chown gateway:gateway (file)
        rule_file = open("/etc/snort/trender/local.rules.old", "r")
        snort_rule_file_list = rule_file.readlines()
        rule_file.close()
        if string_rule in snort_rule_file_list:
            print 'string already in file', string_rule
        else:
            self.flag_file_accessed = True
            rule_file = open("/etc/snort/trender/local.rules.old", "w")
            snort_rule_file_list.append(string_rule)
            rule_file.writelines(snort_rule_file_list)
            rule_file.close()
            print 'string add to file', string_rule

    # same as killing the thread, give the thread a timeout
    def join(self, timeout=None):
        self._stop_flag.set()
        super(Controller, self).join(timeout)