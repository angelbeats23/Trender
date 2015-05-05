#
# Controller Class
# @version 1.0
# @author Dexter Griffiths <11074220@brookes.ac.uk>
#
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

# object containing all logged MySQL IP packet fields
current_alert_db = PacketDB()
# object containing only logged ICMP packet fields
icmp_packet_db = PacketDB()
# object containing only logged HTTP packet fields
syn_packet_db = PacketDB()
# object containing only logged Telnet packet fields
telnet_packet_db = PacketDB()

# object that retrieves variables from the tre_config.ini file
config = ConfigParser.ConfigParser()
config.read('tre_config.ini')


class Controller(threading.Thread):
    def __init__(self):
        # flag to indicate thread is process function or not
        self._stop_flag = threading.Event()
        self.flag_stop_thread = False
        # flag to indicate if the local.rules file has been accessed by the program
        self.flag_file_accessed = False
        # snort service restart command
        self.snort_cmd = "%s %s %s %s" % ('sudo', 'service', 'runsnort', 'restart')

        # PingSweep threshold settings
        self.ps_dangerous_ip = config.get('pingsweep', 'attackers_ip')
        self.ps_time_limit = config.getint('pingsweep', 'recent_timestamp')
        self.ps_packets_time_limit = config.getint('pingsweep', 'compared_timestamp')
        self.ps_packet_threshold = config.getint('pingsweep', 'packet_threshold')

        # Bruteforce threshold settings
        self.bf_time_limit = config.getint('bruteforce', 'recent_timestamp')
        self.bf_packets_time_limit = config.getint('bruteforce', 'compared_timestamp')
        self.bf_packet_threshold = config.getint('bruteforce', 'packet_threshold')

        # SYN Flood threshold settings
        self.dos_time_limit = config.getint('dos', 'recent_timestamp')
        self.dos_packets_time_limit = config.getint('dos', 'compared_timestamp')
        self.dos_packet_threshold = config.getint('dos', 'packet_threshold')

        # Base Login variables
        self.base_user = config.get('base', 'user')
        self.base_pass = config.get('base', 'password')

        # Program delay between processing cycles
        self.delay = config.getint('default', 'delay')
        # local.rules file path variable
        self.path = config.get('default', 'rules_path')

        super(Controller, self).__init__()

    def run(self):
        # Main function that executed to perform the Anomaly Detection
        while not self._stop_flag.is_set():
            self.flag_stop_thread = False
            # caches all packet field data to MySQL database
            self.update_ip_cache()
            # adds all packet field data into a PacketDB object
            self.mysql_database_retrieval()
            # creates a PacketDB object with only ICMP packet field data
            self.create_icmp_packet_db()
            # creates a PacketDB object with only HTTP packet field data
            self.create_syn_packet_db()
            # creates a PacketDB object with only Telnet packet field data
            self.create_telnet_packet_db()
            # Identifies all pingsweep attacker's IP address and creates a snort reject rule
            self.check_for_pingsweep_attacks()
            # Identifies all syn flood attacker's IP address and creates a snort reject rule
            self.check_for_syn_flood_attacks()
            # Identifies all brute force attacker's IP address and creates a snort reject rule
            self.check_brute_force_attacks()
            # add snort rules to local.rules file if they don't already exist
            self.restart_snort(self.flag_file_accessed)
            # empty objects
            self.clean()
            # indicate that the program is not processing any functions
            self.flag_stop_thread = True
            time.sleep(self.delay)

    def status(self):
        # Is the controller object thread alive
        if not self._stop_flag.is_set():
            print("database is being written")
        else:
            print("thread has stopped")

    def get_flag(self):
        return self.flag_stop_thread

    def restart_snort(self, file_accessed):
        # restarts snort
        if file_accessed is True:
            call(self.snort_cmd, shell=True)
            self.flag_file_accessed = False

    def mysql_database_retrieval(self):
        # create a MySQL login object
        db = MySQLdb.connect(host=config.get('mysqld', 'host'), user=config.get('mysqld', 'user'),
                     passwd=config.get('mysqld', 'password'), db=config.get('mysqld', 'db'))
        cursor = db.cursor()
        # open snort database
        cursor.execute("USE snort; ")
        # retrieve Source IP addresses of all logged packets
        cursor.execute("SELECT acid_ip_cache.ipc_fqdn FROM acid_event,acid_ip_cache WHERE "
                       "acid_event.ip_src = acid_ip_cache.ipc_ip ORDER BY acid_event.timestamp; ")
        for row in cursor.fetchall():
            current_alert_db.set_source_ip(row[0])
        # retrieve Source port of all logged packets
        cursor.execute("SELECT layer4_sport FROM acid_event ORDER BY acid_event.timestamp; ")
        for row in cursor.fetchall():
            current_alert_db.set_source_port(row[0])
        # retrieve destination IP addresses of all logged packets
        cursor.execute("SELECT acid_ip_cache.ipc_fqdn FROM acid_event,acid_ip_cache WHERE "
                       "acid_event.ip_dst = acid_ip_cache.ipc_ip ORDER BY acid_event.timestamp; ")
        for row in cursor.fetchall():
            current_alert_db.set_destination_ip(row[0])
        # retrieve destination port of all logged packets
        cursor.execute("SELECT layer4_dport FROM acid_event ORDER BY acid_event.timestamp;")
        for row in cursor.fetchall():
            current_alert_db.set_destination_port(row[0])
        # retrieve alert timestamp of all logged packets
        cursor.execute("SELECT timestamp FROM acid_event ORDER BY acid_event.timestamp;")
        for row in cursor.fetchall():
            current_alert_db.set_timestamp(row[0])
        # retrieve classtype of all logged packets
        cursor.execute("SELECT sig_class.sig_class_name FROM acid_event,sig_class WHERE "
                       "acid_event.sig_class_id = sig_class.sig_class_id ORDER BY acid_event.timestamp;")
        for row in cursor.fetchall():
            current_alert_db.set_class_name(str(row[0]))
        cursor.close()

    def create_syn_packet_db(self):
        # create a PacketDB object with only HTTP (flagged SYN) packets field data only
        for sip in current_alert_db.get_syn_flood_source_ip():
            syn_packet_db.set_source_ip(sip)
        for dip in current_alert_db.get_syn_flood_destination_ip():
            syn_packet_db.set_destination_ip(dip)
        for tp in current_alert_db.get_syn_flood_timestamp():
            syn_packet_db.set_timestamp(str(tp))

    def check_for_syn_flood_attacks(self):
        # cycle through every HTTP (SYN) packet by source IP address and destination IP address
        for sip_item in syn_packet_db.get_sorted_syn_source_ip_list():
            for dip_item in syn_packet_db.get_sorted_syn_destination_ip_list():
                # Create a Threat object for each source IP address and destination IP address
                syn_flood_db = SynFlood()
                syn_flood_db.set_source_ip(sip_item)
                syn_flood_db.set_destination_ip(dip_item)
                # Add timestamps for every source IP address and destination IP address discovered
                for packet in range(0, syn_packet_db.get_timestamp_length()):
                    if sip_item in syn_packet_db.get_source_ip(packet):
                        if dip_item in syn_packet_db.get_destination_ip(packet):
                            syn_flood_db.set_timestamp_list(syn_packet_db.get_timestamp(packet))
                # Identify each SYN Flood attack and create a snort reject rule to block it
                if syn_flood_db.check_all_timestamps(self.dos_time_limit, self.dos_packets_time_limit,
                                                     self.dos_packet_threshold) is True:
                    syn_flood_db.set_snort_rule_string()
                    # add snort reject rule to local.rules file to block the identified intrusion
                    self.write_rules_to_file(syn_flood_db.get_snort_rule_string())
                del syn_flood_db

    def create_icmp_packet_db(self):
        # create a PacketDB object with only ICMP packets field data only
        for sip in current_alert_db.get_icmp_source_ip():
            icmp_packet_db.set_source_ip(sip)
        for dip in current_alert_db.get_icmp_destination_ip():
            icmp_packet_db.set_destination_ip(dip)
        for tp in current_alert_db.get_icmp_timestamp():
            icmp_packet_db.set_timestamp(str(tp))

    def check_for_pingsweep_attacks(self):
        # cycle through every ICMP packet by source IP address
        for sip_item in icmp_packet_db.get_sorted_icmp_source_ip_list():
            # Create a Threat object for each source IP address
            ping_sweep_db = PingSweep()
            ping_sweep_db.set_source_ip(sip_item)
            # Add timestamps and destination IP address for every source IP address discovered
            for packet in range(0, icmp_packet_db.get_source_ip_length()):
                if sip_item in icmp_packet_db.get_source_ip(packet):
                    ping_sweep_db.set_destination_ip_list(icmp_packet_db.get_destination_ip(packet))
                    ping_sweep_db.set_timestamp_list(icmp_packet_db.get_timestamp(packet))
            # Identify each PingSweep attack and create a snort reject rule to block it
            if ping_sweep_db.verified_parameters_timestamps(self.ps_dangerous_ip, self.ps_time_limit,
                                                            self.ps_packets_time_limit, self.ps_packet_threshold) is True:
                ping_sweep_db.set_snort_rule_string()
                # add snort reject rule to local.rules file to block the identified intrusion
                self.write_rules_to_file(ping_sweep_db.get_snort_rule_string())
            del ping_sweep_db

    def create_telnet_packet_db(self):
        # create a PacketDB object with only Telnet packets field data only
        for sip in current_alert_db.get_telnet_source_ip():
            telnet_packet_db.set_source_ip(sip)
        for dip in current_alert_db.get_telnet_destination_ip():
            telnet_packet_db.set_destination_ip(dip)
        for tp in current_alert_db.get_telnet_timestamp():
            telnet_packet_db.set_timestamp(str(tp))

    def check_brute_force_attacks(self):
        # cycle through every Telnet packet by source IP address and destination IP address
        for sip_item in telnet_packet_db.get_sorted_telnet_source_ip_list():
            for dip_item in telnet_packet_db.get_sorted_telnet_destination_ip_list():
                telnet_packet_db.get_sorted_telnet_source_ip_list()
                # Create a Threat object for each source IP address and destination IP address
                brute_force_db = BruteForce()
                brute_force_db.set_source_ip(sip_item)
                brute_force_db.set_destination_ip(dip_item)
                # Add timestamps for every source IP address and destination IP address discovered
                for packet in range(0, telnet_packet_db.get_source_ip_length()):
                    if sip_item in telnet_packet_db.get_source_ip(packet):
                        if dip_item in telnet_packet_db.get_destination_ip(packet):
                            brute_force_db.set_timestamp_list(telnet_packet_db.get_timestamp(packet))
                # Identify each BruteForce attack and create a snort reject rule to block it
                if brute_force_db.check_all_timestamps(self.bf_time_limit, self.bf_packets_time_limit,
                                                       self.bf_packet_threshold) is True:
                    brute_force_db.set_snort_rule_string()
                    # add snort reject rule to local.rules file to block the identified intrusion
                    self.write_rules_to_file(brute_force_db.get_snort_rule_string())
                del brute_force_db

    def write_rules_to_file(self, string_rule):
        snort_rule_file_list = []
        # change the group and user permission for the file to local user. chown gateway:gateway (file)
        rule_file = open(self.path, "r")
        # Open the local.rules file and extract all rules into a list array
        snort_rule_file_list = rule_file.readlines()
        rule_file.close()
        # Each rule will be divide by ; so that the next if statement can compare the strings
        split_str = string_rule.split('";')
        rule_match = False
        # the new rule is divided by ; character so that it can be compared in the if statement
        for rule in snort_rule_file_list:
            if split_str[0] in rule.split('";'):
                rule_match = True
        # If the rule does not previously exist in local.rules file then append it to the file
        if rule_match is False:
            self.flag_file_accessed = True
            rule_file = open(self.path, "w")
            snort_rule_file_list.append(string_rule)
            rule_file.writelines(snort_rule_file_list)
            rule_file.close()
            # print out the successful added rule into local.rules file
            print 'Snort rule added = ', string_rule

    def update_ip_cache(self):
        # create a web page cookie
        cj = cookielib.CookieJar()
        # create a web page querying object
        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
        # add user agent
        opener.addheaders.append(('User-agent', 'Mozilla/4.0'))
        # add URL to access BASE Front-End
        opener.addheaders.append(('Referer', 'http://localhost/base/index.php'))
        # login information
        login_data = urllib.urlencode({'login' : self.base_user, 'password' : self.base_pass, 'submit' : 'submit'})
        # access the login web page
        resp = opener.open('http://localhost/base/index.php', login_data)
        # press the Update Alert Cache button
        login_data = urllib.urlencode({'submit' : 'Update Alert Cache'})
        resp2 = opener.open('http://localhost/base/base_maintenance.php', login_data)
        # press the Rebuild IP cache button
        login_data = urllib.urlencode({'submit' : 'Rebuild IP Cache'})
        resp3 = opener.open('http://localhost/base/base_maintenance.php', login_data)
        resp.close()
        resp2.close()
        resp3.close()

    def clean(self):
        # empty all objects to reuse memory location
        current_alert_db.empty_db()
        icmp_packet_db.empty_db()
        syn_packet_db.empty_db()
        telnet_packet_db.empty_db()

    # same as killing the thread, give the thread a timeout
    def join(self, timeout=None):
        self._stop_flag.set()
        # create a new thread for controller objects
        super(Controller, self).join(timeout)