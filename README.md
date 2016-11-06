This is my project of middlepolice. 
Congratulation! It has published in ACM CCS 16
At First, please see my architecture.pdf
Generally speaking, the topology consists three machines. The Redirect feature you can see my middleproxy repository.
In this repository, it is a simplified topology.But the theory is same.
Topology:
mbox machine===============victim machine

Environment:
OS:Ubuntu 14.04

Setting:
1. Shutdown TSO and GSO in mbox
sudo ethtool -K eth0 gso off
sudo ethtool -K eth0 tso off
haojin@haojin-NUC1:~$ sudo ethtool -k eth0
[sudo] password for haojin:
Features for eth0:
rx-checksumming: on
tx-checksumming: on
        tx-checksum-ipv4: off [fixed]
        tx-checksum-ip-generic: on
        tx-checksum-ipv6: off [fixed]
        tx-checksum-fcoe-crc: off [fixed]
        tx-checksum-sctp: off [fixed]
scatter-gather: on
        tx-scatter-gather: on
        tx-scatter-gather-fraglist: off [fixed]
tcp-segmentation-offload: off
        tx-tcp-segmentation: off
        tx-tcp-ecn-segmentation: off [fixed]
        tx-tcp6-segmentation: off
udp-fragmentation-offload: off [fixed]
generic-segmentation-offload: off
generic-receive-offload: on
large-receive-offload: off [fixed]
rx-vlan-offload: on
tx-vlan-offload: on
ntuple-filters: off [fixed]
receive-hashing: on
highdma: on [fixed]
rx-vlan-filter: off [fixed]
vlan-challenged: off [fixed]
tx-lockless: off [fixed]
netns-local: off [fixed]
tx-gso-robust: off [fixed]
tx-fcoe-segmentation: off [fixed]
tx-gre-segmentation: off [fixed]
tx-ipip-segmentation: off [fixed]
tx-sit-segmentation: off [fixed]
tx-udp_tnl-segmentation: off [fixed]
tx-mpls-segmentation: off [fixed]
fcoe-mtu: off [fixed]
tx-nocache-copy: on
loopback: off [fixed]
rx-fcs: off
rx-all: off
tx-vlan-stag-hw-insert: off [fixed]
rx-vlan-stag-hw-parse: off [fixed]
rx-vlan-stag-filter: off [fixed]
l2-fwd-offload: off [fixed]
haojin@haojin-NUC1:~$

2. Set mss 1300 in victim
sudo ip route add 10.20.101.0/24 dev eth0 advmss 1300

3. run receive in victiom
4. Compile with "gcc -fopenmp -o GenTraffic GenTraffic.c -lm -lpthread" to get send tool. 
Certainly, you can modify source code to control how many data this tool send.
5. Record log information is in /var/log/syslog

Limitation:
ABOUT KVM VIRTUAL MACHINE
I have try on KVM Virtual machines. We meet some problem in Virtual Machines.
The main problems is we can not get the linear sk_buff. This problem is probably caused by TSO and GSO in my opinion.
