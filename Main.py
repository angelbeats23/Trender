#!/usr/bin/python2.7
import MySQLdb
import sys
import time
from PacketDB import PacketDB
from PingSweep import PingSweep

db = MySQLdb.connect(host="localhost", user="snort", passwd="123456", db="snort")
current_alert_db = PacketDB()


def mysql_data_retrieval():
    try:
        cursor = db.cursor()
        '''cursor.execute("SHOW DATABASES; ")
        cursor.execute("select acid_event.signature,acid_ip_cache.ipc_fqdn,acid_event.layer4_sport,acid_event.ip_dst,
        acid_event.layer4_dport,acid_event.timestamp from acid_event,acid_ip_cache where acid_event.ip_src =
        acid_ip_cache.ipc_ip or acid_event.ip_dst = acid_ip_cache.ipc_ip; ")
        cursor.execute("select acid_event.ip_dst, acid_ip_cache.ipc_fqdn from acid_event,acid_ip_cache where
        acid_event.ip_dst = acid_ip_cache.ipc_ip; ")
        cursor.execute("select cid,sig_name,ip_src,layer4_sport,ip_dst,layer4_dport,timestamp from acid_event; ")'''

        cursor.execute("USE snort; ")
        cursor.execute("SELECT sig_name FROM acid_event; ")
        cursor.execute("SELECT acid_ip_cache.ipc_fqdn FROM acid_event,acid_ip_cache WHERE "
                       "acid_event.ip_src = acid_ip_cache.ipc_ip; ")
        cursor.execute("SELECT layer4_sport FROM acid_event; ")
        cursor.execute("SELECT acid_ip_cache.ipc_fqdn FROM acid_event,acid_ip_cache WHERE "
                       "acid_event.ip_dst = acid_ip_cache.ipc_ip; ")
        cursor.execute("SELECT layer4_dport FROM acid_event; ")
        cursor.execute("SELECT timestamp FROM acid_event; ")
        for row in cursor.fetchall():
            print row[0]

    except MySQLdb.Error, e:
        print "Error %d: %s" % (e.args[0], e.args[1])
        sys.exit(1)

    finally:
        if cursor:
            cursor.close()


def main():
    while True:
        mysql_data_retrieval()
        # Create an object from the PingSweep Class
        # new_pingsweep = PingSweep()
        time.sleep(300)


if __name__ == "__main__":

    # Call the main function
    main()

