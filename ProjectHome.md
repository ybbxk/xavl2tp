This is a port of existing xl2tp daemon to work over native Ipv6.

The Xl2tpd currently supports Ipv6 inside ipv4.You can use pppd to negotiate
IPCP version 6 and you would have Ipv6 running over Ipv4 networks.

However in this version ,you could run Ipv4 inside and  Ipv6 as an outside network.


Ipv6 --> udp-->l2tp-->ppp-->ipcp-->ipv4.

This software has been tested over Linux and Freebsd platforms as client and server.
It should also work on other BSD platforms

Please follow the existing documentation of xl2tpd  to install and configure Xavl2tp.

Please download using SVN.

our website :www.xavient.com