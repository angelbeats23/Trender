#!/bin/bash

# Setup needed for gateway in Virtual Box
# two network interfaces (eth0: one connected to the internet or public LAN) other (eth1: connected to private or internal LAN)
# on the internet interface configure it to "Allow All" promiscuous Mode
# 40GB hard drive is required
# 2GB Memory is required
# 1 processor minimum
# install Ubuntu 14.04.1 LTS Server 64bit (ubuntu-14.04.1-server-amd64.iso) via CD drive
# Go through the standard Ubuntu configuration process and create a user account (write it down)
# you may want to enable SSH during the installation process so that you can remote access the server
# enable both network interfaces on the gateway
# place this file into the User's home directory and change the permissions to the file to execute (chmod 710)
# launch the program (sudo ./setup.sh)


# updates Ubuntu 14.04.1 LTS Server 64bit
#sudo apt-get update -y ; sudo apt-get upgrade -y;

# Setup connection sharing between interfaces in Ubuntu

#configure internal network (eth1) for static IP
sudo ifconfig eth1 up
sudo ip addr add 10.0.0.1/24 dev eth1
sudo sh -c " echo auto eth1 >> /etc/network/interfaces"
sudo sh -c " echo iface eth1 inet static >> /etc/network/interfaces"
sudo sh -c " echo address 10.0.0.1 >> /etc/network/interfaces"
sudo sh -c " echo network 10.0.0.0 >> /etc/network/interfaces"
sudo sh -c " echo netmask 255.255.255.0 >> /etc/network/interfaces"
sudo sh -c " echo broadcast 10.0.0.255 >> /etc/network/interfaces"

#configure iptables NAT translation to allow traffic through Ubuntu server
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
sudo iptables -t nat -A PREROUTING -j NFQUEUE --queue-num 2

# save iptables
sudo iptables-save | sudo tee /etc/iptables.sav

# restores iptables with the correct commands even after reboot
sudo sed -i 's/# By default this script does nothing./iptables-restore < \/etc\/iptables.sav/g' /etc/rc.local

# allow IP forwarding between both interfaces
sudo sh -c "echo 1 > /proc/sys/net/ipv4/ip_forward"

# Another Configuration to allow IP forwarding between interfaces
sudo sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf

# Snort

# snort dependencies
sudo apt-get install make -y;
sudo apt-get install libpcap-dev -y;
sudo apt-get install bison -y;
sudo apt-get install flex -y;
sudo apt-get install gcc -y;
sudo apt-get install libpcre3-dev -y;
sudo apt-get install iptables-dev -y;
sudo apt-get install zlib1g-dev -y;
# Barnyard2 dependencies
sudo apt-get install autoconf -y;
sudo apt-get install libtool -y;
sudo apt-get install checkinstall -y;
sudo apt-get install build-essential -y;
sudo apt-get install libmysqld-dev -y;
sudo apt-get install git -y;

sudo apt-get install libnet1-dev libnetfilter-queue-dev libnfnetlink-dev libnfnetlink0 libmnl-dev -y;

# install barnyard2 dependency libdnet
sudo wget http://libdnet.googlecode.com/files/libdnet-1.12.tgz
sudo tar zxvf libdnet-1.12.tgz
cd libdnet-1.12/
./configure "CFLAGS=-fPIC -g -O2"
make
sudo checkinstall
# press "enter" through all the command dialogues
sudo dpkg -i libdnet_1.12-1_amd64.deb

# changes to the home directory
cd


sudo wget https://www.snort.org/downloads/snort/daq-2.0.4.tar.gz
sudo tar xvfz daq-2.0.4.tar.gz
cd daq-2.0.4/
./configure --disable-ipq-module --libdir=/usr/lib --includedir=/usr/include ; make; sudo make install

# changes to the home directory
cd

sudo apt-get install snort -y;
# [enter LAN subnet e.g. 10.0.0.0/24]

# additions here.

sudo sed -i ' s/# additions here./drop icmp any any <> any any \(msg:\"ICMP PACKET TEST\"; classtype:not-suspicious; sid:100002; rev:1;\)/g' /etc/snort/rules/local.rules

sudo sed -i " s/# config daq: <type>/config daq: nfq/g" /etc/snort/snort.conf
sudo sed -i " s/# config daq_dir: <dir>/config daq_dir: \/usr\/lib\/daq/g" /etc/snort/snort.conf
sudo sed -i " s/# config daq_mode: <mode>/config daq_mode: inline/g" /etc/snort/snort.conf
sudo sed -i " s/# config daq_var: <var>/config daq_var: queue=2/g" /etc/snort/snort.conf

# configure snort to create output log files (in binary) that barnyard can read
sudo sed -i ' s/output unified2: filename snort.log, limit 128, nostamp, mpls_event_types, vlan_event_types/output unified2: filename snort.log, limit 128, mpls_event_types, vlan_event_types/g' /etc/snort/snort.conf
sudo sed -i ' s/# Recommended for most installs/output unified2: filename snort.u2, limit 128/g' /etc/snort/snort.conf
sudo sed -i ' s/# output alert_unified2: filename snort.alert, limit 128, nostamp/output alert_unified2: filename snort.alert, limit 128, nostamp/g' /etc/snort/snort.conf
sudo sed -i ' s/# output log_unified2: filename snort.log, limit 128, nostamp/output log_unified2: filename snort.log, limit 128, nostamp/g' /etc/snort/snort.conf
sudo sed -i ' s/# output alert_syslog: LOG_AUTH LOG_ALERT/output alert_syslog: LOG_AUTH LOG_ALERT/g' /etc/snort/snort.conf

# TODO locate all the rule files that need to be commented out
sudo sed -i 's/include \$RULE_PATH\/attack-responses.rules/#include \$RULE_PATH\/attack-responses.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/backdoor.rules/#include \$RULE_PATH\/backdoor.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/bad-traffic.rules/#include \$RULE_PATH\/bad-traffic.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/chat.rules/#include \$RULE_PATH\/chat.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/ddos.rules/#include \$RULE_PATH\/ddos.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/dns.rules/#include \$RULE_PATH\/dns.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/dos.rules/#include \$RULE_PATH\/dos.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/experimental.rules/#include \$RULE_PATH\/experimental.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/exploit.rules/#include \$RULE_PATH\/exploit.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/finger.rules/#include \$RULE_PATH\/finger.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/ftp.rules/#include \$RULE_PATH\/ftp.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/icmp-info.rules/#include \$RULE_PATH\/icmp-info.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/icmp.rules/#include \$RULE_PATH\/icmp.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/imap.rules/#include \$RULE_PATH\/imap.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/info.rules/#include \$RULE_PATH\/info.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/misc.rules/#include \$RULE_PATH\/misc.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/multimedia.rules/#include \$RULE_PATH\/multimedia.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/mysql.rules/#include \$RULE_PATH\/mysql.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/netbios.rules/#include \$RULE_PATH\/netbios.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/nntp.rules/#include \$RULE_PATH\/nntp.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/oracle.rules/#include \$RULE_PATH\/oracle.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/other-ids.rules/#include \$RULE_PATH\/other-ids.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/p2p.rules/#include \$RULE_PATH\/p2p.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/policy.rules/#include \$RULE_PATH\/policy.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/pop2.rules/#include \$RULE_PATH\/pop2.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/pop3.rules/#include \$RULE_PATH\/pop3.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/rpc.rules/#include \$RULE_PATH\/rpc.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/rservices.rules/#include \$RULE_PATH\/rservices.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/scan.rules/#include \$RULE_PATH\/scan.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/smtp.rules/#include \$RULE_PATH\/smtp.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/snmp.rules/#include \$RULE_PATH\/snmp.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/sql.rules/#include \$RULE_PATH\/sql.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/telnet.rules/#include \$RULE_PATH\/telnet.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/tftp.rules/#include \$RULE_PATH\/tftp.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/virus.rules/#include \$RULE_PATH\/virus.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/web-attacks.rules/#include \$RULE_PATH\/web-attacks.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/web-cgi.rules/#include \$RULE_PATH\/web-cgi.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/web-client.rules/#include \$RULE_PATH\/web-client.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/web-coldfusion.rules/#include \$RULE_PATH\/web-coldfusion.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/web-frontpage.rules/#include \$RULE_PATH\/web-frontpage.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/web-iis.rules/#include \$RULE_PATH\/web-iis.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/web-misc.rules/#include \$RULE_PATH\/web-misc.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/web-php.rules/#include \$RULE_PATH\/web-php.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/x11.rules/#include \$RULE_PATH\/x11.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/community-sql-injection.rules/#include \$RULE_PATH\/community-sql-injection.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/community-web-client.rules/#include \$RULE_PATH\/community-web-client.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/community-web-dos.rules/#include \$RULE_PATH\/community-web-dos.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/community-web-iis.rules/#include \$RULE_PATH\/community-web-iis.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/community-web-misc.rules/#include \$RULE_PATH\/community-web-misc.rules/g' /etc/snort/snort.conf
sudo sed -i 's/include \$RULE_PATH\/community-web-php.rules/#include \$RULE_PATH\/community-web-php.rules/g' /etc/snort/snort.conf

# remove snort log files
sudo rm /var/log/snort/snort.log

# restart snort
sudo service snort restart

# change file permissions
sudo chown snort:snort /var/log/snort

# Barnyard2

# changes to the home directory
cd

# install barnyard2
cd /usr/src/
sudo git clone git://github.com/firnsy/barnyard2.git
cd barnyard2/
sudo ./autogen.sh
sudo autoreconf -fvi -I ./m4
sudo ./configure --with-mysql --with-mysql-libraries=/usr/lib/x86_64-linux-gnu
sudo make
sudo make install
sudo cp /usr/local/etc/barnyard2.conf /etc/snort
sudo cp schemas/create_mysql /usr/src
sudo mkdir /var/log/barnyard2

# configure barnyard2 configuration file
cd /etc/snort/
sudo sed -i ' s/#   output alert_syslog: LOG_AUTH LOG_INFO/output alert_syslog: LOG_AUTH LOG_ALERT/g' /etc/snort/barnyard2.conf
sudo sed -i ' s/#   output database: log, mysql, user=root password=test dbname=db host=localhost/output database: log, mysql, user=snort password=123456 dbname=snort host=localhost/g' /etc/snort/barnyard2.conf
sudo sed -i ' s/output alert_fast: stdout/output alert_fast/g' /etc/snort/barnyard2.conf
sudo sed -i ' s/#config daemon/config daemon/g' /etc/snort/barnyard2.conf

# changes to the home directory
cd

# MySQL

# install mysql (tell user to change the default passwords once fully installed)
sudo apt-get install mysql-server -y;
# [ enter Mysql-server user:root password:123456 ]

# create snort mysql database and grant user snort full access to database
for i in "create database snort;" "create database archive;" "grant usage on snort.* to snort@localhost;" "grant usage on archive.* to snort@localhost;" "set password for snort@localhost=PASSWORD('123456');" "grant all privileges on snort.* to snort@localhost;" "grant all privileges on archive.* to snort@localhost;" "flush privileges;" "exit"
do
    echo $i >> mysqlcommands
done
sudo mysql -u root --password=123456 < mysqlcommands
rm mysqlcommands

# creates tables in mysql snort database
for a in "use snort;" "source /usr/src/create_mysql;" "exit"
do
    echo $a >> mysqlcommands
done
sudo mysql -u root --password=123456 < mysqlcommands
rm mysqlcommands

# fix sid-msg.map issue
cd /usr/share/oinkmaster/
sudo bash -c "sudo ./create-sidmap.pl /etc/snort/rules > /etc/snort/sid-msg.map"

#create creat barnyard2 auto run file
cd /etc/init.d/
sudo touch runbarnyard2
for b in "#!/bin/sh" "case \$1 in" "start)" "echo \"Starting Barnyard2\"" "sudo bash -c \"sudo /usr/local/bin/barnyard2 -c /etc/snort/barnyard2.conf -d /var/log/snort/ -f snort.log -w /var/log/barnyard2/barnyard2.waldo\"" "echo 'Barnyard2 started.'" ";;" "stop)" "echo \"Stopping Barnyard2\"" "sudo killall barnyard2" "echo 'Barnyard2 stopped.'" ";;" "restart)" "\$0 stop" "sleep 4" "\$0 start" ";;" "*)" "echo \"usage: \$0 (start|stop|restart)\"" ";;" "esac" "exit 0"
do
    echo $b >> runbarnyard2
done
sudo chmod 700 /etc/init.d/runbarnyard2
sudo update-rc.d runbarnyard2 defaults

# start barnyard2
sudo /etc/init.d/runbarnyard2 start

# changes to the home directory
cd

# Apache2

# Apache2 dependencies
sudo apt-get install apache2 -y;
sudo apt-get install libapache2-mod-php5 -y;
sudo apt-get install libphp-adodb -y;
# [enter message OK]

# change apache2 error report settings
sudo sed -i 's/error_reporting = E_ALL \& ~E_DEPRECATED \& ~E_STRICT/error_reporting = E_ALL \& ~E_NOTICE/g' /etc/php5/apache2/php.ini
sudo sed -i 's/# access here, or in any related virtual host./\<Directory \/var\/www\/html\/base\>\n   AllowOverride All\n    Require all granted\n\<\/Directory\>\n/g' /etc/apache2/apache2.conf

# restart apache2 server
sudo service apache2 restart

# Basic Analysis Secuirty Engine

# BASE dependencies
sudo apt-get install php-pear -y;
sudo apt-get install libwww-perl -y;
sudo apt-get install php5-gd -y;
sudo pear config-set preferred_state alpha
sudo pear channel-update pear.php.net
sudo pear install --alldeps Image_Color Image_Canvas Image_Graph

# BASE Install
cd /usr/src
sudo wget http://sourceforge.net/projects/secureideas/files/BASE/base-1.4.5/base-1.4.5.tar.gz
sudo tar -zxf base-1.4.5.tar.gz
sudo cp -r base-1.4.5 /var/www/html/base
sudo chown -R www-data:www-data /var/www/html/base
sudo service apache2 restart
# account setup is needed to log into BASE when first loading webpage
# set path : /usr/share/php/adodb
# set everything with Database name/user = snort
# Database Host = localhost
# tick 'Use Archive Database'
# Archive Database : archive
# tick Use Authentication System
# set passwords as 123456
# Click ' Create baseAG'
# Click ' Now continue to Step 5 '

# Set BASE configurations
sudo sed -i 's/\$colored_alerts = 0\;/\$colored_alerts = 1\;/g' /var/www/html/base/base_conf.php

# restart snort and barnyard2
sudo service snort restart
sudo /etc/init.d/runbarnyard2 restart


