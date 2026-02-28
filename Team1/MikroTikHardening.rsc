:local T 19
:local wanIF "ether1"
:local lanIF "ether2"
:local lanNet "192.168.19.0/24"
:local webIP "192.168.19.5"
:local dbIP "192.168.19.7"
:local dnsIP "192.168.19.12"
:local bakIP "192.168.19.15"
:local lanMgmt "192.168.19.0/24"
:local extGW "172.18.0.1"
:local extDNS "172.18.0.12"
:local extCA "172.18.0.38"
:local extCDN "172.18.13.25"
:local jumpIP "172.18.12.15"

/interface list
add name=WAN comment="NCAE WAN list"
add name=LAN comment="NCAE LAN list"

/interface list member
add interface=ether1 list=WAN
add interface=ether2 list=LAN

/ip firewall address-list
add list=MGMTLAN address=$lanMgmt comment="LAN management scope"
add list=SRVWEB address=$webIP comment="Web server"
add list=SRVDNS address=$dnsIP comment="DNS server"
add list=SRVDB address=$dbIP comment="DB server"
add list=SRVBAK address=$bakIP comment="Backup server"
add list=PERMITTEDEXT address=$extGW comment="Competition gateway"
add list=PERMITTEDEXT address=$extDNS comment="External DNS"
add list=PERMITTEDEXT address=$extCA comment="Certificate Authority"
add list=PERMITTEDEXT address=$extCDN comment="CDN"
add list=MGMTJUMP address=($jumpIP."/32") comment="Jump host"

/ip service
set telnet disabled=yes
set ftp disabled=yes
set www disabled=yes
set www-ssl disabled=yes
set ssh disabled=yes
set winbox disabled=yes
set api disabled=yes
set api-ssl disabled=yes

/ip firewall filter
add chain=input action=drop connection-state=invalid comment="IN drop invalid" log=yes log-prefix="ININVALID"
add chain=input action=accept connection-state=established,related comment="IN accept established,related"
add chain=input action=accept protocol=icmp in-interface-list=WAN comment="IN accept ICMP from WAN scoring" log=yes log-prefix="INICMP"
add chain=input action=accept protocol=icmp in-interface-list=LAN comment="IN accept ICMP from LAN"
add chain=input action=drop in-interface-list=WAN comment="IN drop all other WAN" log=yes log-prefix="INWANDROP"
add chain=input action=drop comment="IN implicit deny" log=yes log-prefix="INDROP"
add chain=forward action=drop connection-state=invalid comment="FW drop invalid" log=yes log-prefix="FWINVALID"
add chain=forward action=accept connection-state=established,related comment="FW accept established,related"
add chain=forward action=accept connection-nat-state=dstnat comment="FW allow dstnat forwards" log=yes log-prefix="FWDNATOK"
add chain=forward action=accept in-interface-list=LAN dst-address-list=SRVDNS protocol=udp dst-port=53 comment="FW LAN to DNS UDP"
add chain=forward action=accept in-interface-list=LAN dst-address-list=SRVDNS protocol=tcp dst-port=53 comment="FW LAN to DNS TCP"
add chain=forward action=accept in-interface-list=LAN dst-address-list=SRVDB protocol=tcp dst-port=5432 comment="FW LAN to Postgres 5432"
add chain=forward action=accept in-interface-list=LAN src-address-list=MGMTLAN dst-address-list=SRVWEB protocol=tcp dst-port=22 comment="FW MGMTLAN to WWW SSH"
add chain=forward action=accept in-interface-list=LAN src-address-list=MGMTLAN dst-address-list=SRVDNS protocol=tcp dst-port=22 comment="FW MGMTLAN to DNS SSH"
add chain=forward action=accept in-interface-list=LAN src-address-list=MGMTLAN dst-address-list=SRVDB protocol=tcp dst-port=22 comment="FW MGMTLAN to DB SSH"
add chain=forward action=accept in-interface-list=LAN src-address-list=MGMTLAN dst-address-list=SRVBAK protocol=tcp dst-port=22 comment="FW MGMTLAN to BACKUP SSH"
add chain=forward action=accept in-interface-list=LAN out-interface-list=WAN dst-address-list=PERMITTEDEXT protocol=tcp dst-port=80,443 comment="FW LAN to permitted ext TCP 80443"
add chain=forward action=accept in-interface-list=LAN out-interface-list=WAN dst-address-list=PERMITTEDEXT protocol=udp dst-port=53 comment="FW LAN to permitted ext DNS UDP"
add chain=forward action=accept in-interface-list=LAN out-interface-list=WAN dst-address-list=PERMITTEDEXT protocol=tcp dst-port=53 comment="FW LAN to permitted ext DNS TCP"
add chain=forward action=accept in-interface-list=LAN out-interface-list=WAN dst-address=$extGW comment="FW LAN to competition gateway"
add chain=forward action=drop in-interface-list=LAN out-interface-list=WAN protocol=udp dst-port=53 comment="FW block LAN direct external DNS UDP" log=yes log-prefix="FWDNSLEAK"
add chain=forward action=drop in-interface-list=LAN out-interface-list=WAN protocol=tcp dst-port=53 comment="FW block LAN direct external DNS TCP" log=yes log-prefix="FWDNSLEAK"
add chain=forward action=drop in-interface-list=LAN out-interface-list=WAN comment="FW drop all other LAN egress" log=yes log-prefix="FWEGRESSDROP"
add chain=forward action=drop in-interface-list=WAN out-interface-list=LAN connection-nat-state=!dstnat comment="FW drop WAN to LAN not dstnat" log=yes log-prefix="FWWANNODNAT"
add chain=forward action=drop comment="FW implicit deny" log=yes log-prefix="FWDROP"

/ip firewall nat
add chain=dstnat action=dst-nat in-interface-list=LAN protocol=udp dst-port=53 dst-address=!192.168.19.12 to-addresses=192.168.19.12 to-ports=53 comment="NAT redirect rogue LAN DNS UDP to internal DNS"
add chain=dstnat action=dst-nat in-interface-list=LAN protocol=tcp dst-port=53 dst-address=!192.168.19.12 to-addresses=192.168.19.12 to-ports=53 comment="NAT redirect rogue LAN DNS TCP to internal DNS"
add chain=srcnat action=masquerade out-interface-list=WAN comment="NAT masquerade LAN to WAN"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=tcp dst-port=80 to-addresses=$webIP to-ports=80 comment="DNAT HTTP to WEB"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=tcp dst-port=443 to-addresses=$webIP to-ports=443 comment="DNAT HTTPS to WEB"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=udp dst-port=53 to-addresses=$dnsIP to-ports=53 comment="DNAT DNS UDP to DNS"
add chain=dstnat action=dst-nat in-interface-list=WAN protocol=tcp dst-port=53 to-addresses=$dnsIP to-ports=53 comment="DNAT DNS TCP to DNS"
add chain=dstnat action=dst-nat in-interface-list=WAN src-address-list=MGMTJUMP protocol=tcp dst-port=2205 to-addresses=$webIP to-ports=22 comment="DNAT JUMP to WWW SSH"
add chain=dstnat action=dst-nat in-interface-list=WAN src-address-list=MGMTJUMP protocol=tcp dst-port=2207 to-addresses=$dbIP to-ports=22 comment="DNAT JUMP to DB SSH"
add chain=dstnat action=dst-nat in-interface-list=WAN src-address-list=MGMTJUMP protocol=tcp dst-port=2212 to-addresses=$dnsIP to-ports=22 comment="DNAT JUMP to DNS SSH"
add chain=dstnat action=dst-nat in-interface-list=WAN src-address-list=MGMTJUMP protocol=tcp dst-port=2215 to-addresses=$bakIP to-ports=22 comment="DNAT JUMP to BACKUP SSH"