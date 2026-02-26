#!/bin/bash

## Make sure BIND is installed
sudo dnf install bind bind-utils


## Restrict listening for the localhost
sudo sed -i '7,8 s/^/#/' /etc/named.conf

## Add section in configuration file for zones (Replace t with 3rd octet of network address)
sudo cat <<EOF >> /etc/named.conf

//forward zone
zone "ncaecybergames.org" IN {
     type master;
     file "forward.ncaecybergames.org";
     allow-update { none; };
    allow-query {any; };
};
//reverse zone (Internal)
zone "t.168.192.in-addr.arpa" IN {
     type master;
     file "reverse.ncaecybergames.org";
     allow-update { none; };
    allow-query { any; };
};
//reverse zone (External)
zone "18.172.in-addr.arpa" IN {
	 type master;
	 file "reverse.ncaecybergames.org";
	 allow-update { none; };
	allow-query {any; };	
};
EOF


## Create the forward record (Fill in correct subdomains)
sudo cat <<EOF > /var/named/forward.ncaecybergames.org
$TTL 86400
@ IN SOA ncaecybergames.org. admin.ncaecybergames.org. (
    2026022801 ;Serial
    3600 ;Refresh
    1800 ;Retry
    604800 ;Expire
    86400 ;Minimum TTL
)

;Name Server Information
@ IN NS $HOSTNAME.

;IP for Name Server
$HOSTNAME IN A 192.168.t.12

;A Record for IP address to Hostname
EOF

## Create the reverse record (Fill in correct subdomains)
sudo cat <<EOF > /var/named/reverse.ncaecybergames.org
$TTL 86400
@ IN SOA ncaecybergames.org. admin.ncaecybergames.org. (
    2026022801 ;Serial
    3600 ;Refresh
    1800 ;Retry
    604800 ;Expire
    86400 ;Minimum TTL
)
;Name Server Information
@ IN NS $HOSTNAME.

;Reverse lookup for Name Server
12 IN PTR $HOSTNAME.

;PTR Record IP address to HostName


;PTR Record IP address to HostName
EOF


#Restart the named service
sudo systemctl restart named







