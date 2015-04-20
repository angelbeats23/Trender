import threading
import MySQLdb
import sys
import time
import ConfigParser
import urllib
import urllib2
import cookielib
from subprocess import call
from PacketDB import PacketDB
from Threats import *

current_alert_db = PacketDB()
icmp_packet_db = PacketDB()
syn_packet_db = PacketDB()
telnet_packet_db = PacketDB()

config = ConfigParser.ConfigParser()
config.read('tre_config.ini')


class Controller(threading.Thread):
    def __init__(self):
        self._stop_flag = threading.Event()
        self.flag_stop_thread = False
        self.flag_file_accessed = False
        self.snort_cmd = "%s %s %s %s" % ('sudo', 'service', 'snort', 'stop')
        self.snort_cmd2 = "%s %s %s %s %s %s %s %s" % ('sudo', 'snort', '-l', '/var/log/snort', '-c', '/etc/snort/snort.conf', '-D', '-Q')

        self.ps_dangerous_ip = config.get('pingsweep', 'attackers_ip')
        self.ps_time_limit = config.getint('pingsweep', 'packet_time_limit')
        self.ps_packets_time_limit = config.getint('pingsweep', 'packets_time_limit')
        self.ps_packet_threshold = config.getint('pingsweep', 'packet_threshold')

        self.bf_time_limit = config.getint('bruteforce', 'packet_time_limit')
        self.bf_packets_time_limit = config.getint('bruteforce', 'packets_time_limit')
        self.bf_packet_threshold = config.getint('bruteforce', 'packet_threshold')

        self.dos_time_limit = config.getint('dos', 'packet_time_limit')
        self.dos_packets_time_limit = config.getint('dos', 'packets_time_limit')
        self.dos_packet_threshold = config.getint('dos', 'packet_threshold')

        self.base_user = config.get('base', 'user')
        self.base_pass = config.get('base', 'password')

        self.delay = config.getint('default', 'delay')
        self.path = config.get('default', 'rules_path')

        super(Controller, self).__init__()

    # while thread running
    def run(self):
        while not self._stop_flag.is_set():
            # business
            self.flag_stop_thread = False
            self.update_ip_cache()
            self.mysql_database_retrieval()
            self.create_icmp_packet_db()
            self.create_syn_packet_db()
            self.create_telnet_packet_db()
            self.check_for_pingsweep_attacks()
            self.check_for_syn_flood_attacks()
            self.check_brute_force_attacks()
            self.restart_snort(self.flag_file_accessed)
            self.clean()
            self.flag_stop_thread = True
            time.sleep(self.delay)

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
            call(self.snort_cmd2, shell=True)
            self.flag_file_accessed = False

    def mysql_database_retrieval(self):
        db = MySQLdb.connect(host=config.get('mysqld', 'host'), user=config.get('mysqld', 'user'),
                     passwd=config.get('mysqld', 'password'), db=config.get('mysqld', 'db'))
        cursor = db.cursor()
        cursor.execute("USE snort; ")
        cursor.execute("SELECT acid_ip_cache.ipc_fqdn FROM acid_event,acid_ip_cache WHERE "
                       "acid_event.ip_src = acid_ip_cache.ipc_ip ORDER BY acid_event.timestamp; ")
        for row in cursor.fetchall():
            current_alert_db.set_source_ip(row[0])
        cursor.execute("SELECT layer4_sport FROM acid_event ORDER BY acid_event.timestamp; ")
        for row in cursor.fetchall():
            current_alert_db.set_source_port(row[0])
        cursor.execute("SELECT acid_ip_cache.ipc_fqdn FROM acid_event,acid_ip_cache WHERE "
                       "acid_event.ip_dst = acid_ip_cache.ipc_ip ORDER BY acid_event.timestamp; ")
        for row in cursor.fetchall():
            current_alert_db.set_destination_ip(row[0])
            # there is an issue with barnyard storing destination ip addresses in mysql
            # primarily due to the fact that it only stores cached fqdn that have been
            # queried. the only way to do this is by login into base and clicking on every
            # packets destination ip address link which will make it perform a dns lookup.
        cursor.execute("SELECT layer4_dport FROM acid_event ORDER BY acid_event.timestamp;")
        for row in cursor.fetchall():
            current_alert_db.set_destination_port(row[0])
        cursor.execute("SELECT timestamp FROM acid_event ORDER BY acid_event.timestamp;")
        for row in cursor.fetchall():
            current_alert_db.set_timestamp(row[0])
        cursor.execute("SELECT sig_class.sig_class_name FROM acid_event,sig_class WHERE "
                       "acid_event.sig_class_id = sig_class.sig_class_id ORDER BY acid_event.timestamp;")
        for row in cursor.fetchall():
            current_alert_db.set_class_name(str(row[0]))
        cursor.close()

    # identify all syn packets and store them in a object
    def create_syn_packet_db(self):
        for sip in current_alert_db.get_syn_flood_source_ip():
            syn_packet_db.set_source_ip(sip)
        for dip in current_alert_db.get_syn_flood_destination_ip():
            syn_packet_db.set_destination_ip(dip)
        # for d_port in current_alert_db.get_syn_flood_destination_port():
        #     syn_packet_db.set_destination_port(d_port)
        for tp in current_alert_db.get_syn_flood_timestamp():
            syn_packet_db.set_timestamp(str(tp))

    def check_for_syn_flood_attacks(self):
        # identifies every packet that matches every possible packet from the unsorted syn_packet_db
        for sip_item in syn_packet_db.get_sorted_syn_source_ip_list():
            for dip_item in syn_packet_db.get_sorted_syn_destination_ip_list():
                syn_flood_db = SynFlood()
                syn_flood_db.set_source_ip(sip_item)
                syn_flood_db.set_destination_ip(dip_item)
                # searches for every packets timestamp that matches all previous criteria
                for packet in range(0, syn_packet_db.get_timestamp_length()):
                    if sip_item in syn_packet_db.get_source_ip(packet):
                        if dip_item in syn_packet_db.get_destination_ip(packet):
                            syn_flood_db.set_timestamp_list(syn_packet_db.get_timestamp(packet))
                if syn_flood_db.check_all_timestamps(self.dos_time_limit, self.dos_packets_time_limit,
                                                     self.dos_packet_threshold) is True:
                    syn_flood_db.set_snort_rule_string()
                    self.write_rules_to_file(syn_flood_db.get_snort_rule_string())
                del syn_flood_db

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
                    ping_sweep_db.set_destination_ip_list(icmp_packet_db.get_destination_ip(packet))
                    ping_sweep_db.set_timestamp_list(icmp_packet_db.get_timestamp(packet))
            if ping_sweep_db.verified_parameters_timestamps(self.ps_dangerous_ip, self.ps_time_limit,
                                                            self.ps_packets_time_limit, self.ps_packet_threshold) is True:
                ping_sweep_db.set_snort_rule_string()
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
        # go through every possible source ip address
        for sip_item in telnet_packet_db.get_sorted_telnet_source_ip_list():
            for dip_item in telnet_packet_db.get_sorted_telnet_destination_ip_list():
                telnet_packet_db.get_sorted_telnet_source_ip_list()
                brute_force_db = BruteForce()
                brute_force_db.set_source_ip(sip_item)
                brute_force_db.set_destination_ip(dip_item)
                # if icmp packet has source ip address add its destination and timestamp
                for packet in range(0, telnet_packet_db.get_source_ip_length()):
                    if sip_item in telnet_packet_db.get_source_ip(packet):
                        if dip_item in telnet_packet_db.get_destination_ip(packet):
                            brute_force_db.set_timestamp_list(telnet_packet_db.get_timestamp(packet))
                if brute_force_db.check_all_timestamps(self.bf_time_limit, self.bf_packets_time_limit,
                                                       self.bf_packet_threshold) is True:
                    brute_force_db.set_snort_rule_string()
                    self.write_rules_to_file(brute_force_db.get_snort_rule_string())
                del brute_force_db

    def write_rules_to_file(self, string_rule):
        snort_rule_file_list = []
        # change the group and user permission for the file to local user. chown gateway:gateway (file)
        rule_file = open(self.path, "r")
        snort_rule_file_list = rule_file.readlines()
        rule_file.close()
        split_str = string_rule.split('";')
        rule_match = False
        for rule in snort_rule_file_list:
            if split_str[0] in rule.split('";'):
                rule_match = True
        if rule_match is False:
            self.flag_file_accessed = True
            rule_file = open(self.path, "w")
            snort_rule_file_list.append(string_rule)
            rule_file.writelines(snort_rule_file_list)
            rule_file.close()
            print 'Snort rule added = ', string_rule

    def update_ip_cache(self):
        # cookie storage
        cj = cookielib.CookieJar()
        # create an opener
        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
        opener.addheaders.append(('User-agent', 'Mozilla/4.0'))
        opener.addheaders.append(('Referer', 'http://localhost/base/index.php'))
        login_data = urllib.urlencode({'login' : self.base_user, 'password' : self.base_pass, 'submit' : 'submit'})
        resp = opener.open('http://localhost/base/index.php', login_data)
        login_data = urllib.urlencode({'submit' : 'Update Alert Cache'})
        resp2 = opener.open('http://localhost/base/base_maintenance.php', login_data)
        login_data = urllib.urlencode({'submit' : 'Update IP Cache'})
        resp3 = opener.open('http://localhost/base/base_maintenance.php', login_data)
        resp.close()
        resp2.close()
        resp3.close()

    def clean(self):
        current_alert_db.empty_db()
        icmp_packet_db.empty_db()
        syn_packet_db.empty_db()
        telnet_packet_db.empty_db()

    # same as killing the thread, give the thread a timeout
    def join(self, timeout=None):
        self._stop_flag.set()
        super(Controller, self).join(timeout)