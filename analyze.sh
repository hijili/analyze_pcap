#!/bin/bash -ex

SELF_IP=192.168.11.2

pcap=$1;
[ -z $pcap ] && { echo "Input pcap file!"; exit 1; }

tcpdump -r $pcap src $SELF_IP  | sed -ne "s/.* > \([^:]*\):.*/\1/p" | sort | uniq -c > send_host.txt
tcpdump -r $pcap dst $SELF_IP  | sed -ne "s/.* \([^:]*\) > .*/\1/p" | sort | uniq -c > recv_host.txt

# I want to whois cache...
# for host in $(awk '{print $2}' send_host.txt  | sed -e 's/\.[^\.]\+$//' | uniq) ; do
# 	echo ===== $host =====
# 	whois $host | grep -e NetName: -e Organization:
# done

