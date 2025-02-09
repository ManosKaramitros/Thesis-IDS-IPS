#!/bin/bash

#Shield For DoS Attacks

counter="$1"
shift
unified_array_mal=("$@")

dos_source_check=0

#######################################################################################
#Block the Malicious IP Addresses and Implement Rate Limiting for Specified Protocol
#######################################################################################

sudo nft add table ip filter
sudo nft add chain ip filter input { type filter hook input priority 0 \; }
sudo nft add chain ip filter output { type filter hook output priority 0 \; }



if [ ${#unified_array_mal[@]} -ne 0 ]; then

   ((dos_source_check++))

   for ip_to_ban in "${unified_array_mal[@]}"; do


       sudo nft add rule ip filter input ip saddr "$ip_to_ban" drop
       sudo nft add rule ip filter output ip daddr "$ip_to_ban" drop


   done

fi


if [ "$counter" == "UDP" ]; then

     sudo nft add rule ip filter input ip protocol udp limit rate 100/second burst 50 packets drop
     sudo nft add rule ip filter output ip protocol udp limit rate 100/second burst 50 packets drop

elif [ "$counter" == "TCP" ]; then

     sudo nft add rule ip filter input ip protocol tcp limit rate 100/second drop
     sudo nft add rule ip filter output ip protocol tcp limit rate 100/second drop


elif [ "$counter" == "ICMP" ]; then

     sudo nft add rule ip filter input ip protocol icmp limit rate 100/second drop
     sudo nft add rule ip filter output ip protocol icmp limit rate 100/second drop

fi



if [[ "$dos_source_check" -ne 0 ]]; then

     echo
     echo
     echo "*** Attacker was Blocked and Rate Limiting for $counter Traffic was applied Successfully ***"

else
     echo
     echo
     echo "*** Rate Limiting was applied Successfully for $counter Traffic ***"
fi
