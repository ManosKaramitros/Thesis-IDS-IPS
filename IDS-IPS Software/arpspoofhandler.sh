#!/bin/bash

#Handler For ARP Spoofing Attacks

echo
echo
echo "--- Potential ARP Spoof Detected ---"
echo
sleep 6
sudo kill -15 $SNORT_PID
sleep 1

###################################
#Source & Target Identification
###################################

echo
echo
echo "Anilyzing Snort Logs to Extract Crucial Information about the Attack"

process_flag "ARP" "6" "17" "2" "6" > /dev/null 2>&1

echo
echo
echo "Logs Check Came back with the Following:"
echo
echo "Source MAC(s): ${source_macs_sorted[@]}"
echo
echo "Destination -- Protected Network -- MAC(s): ${home_macs_sorted[@]}"
echo

###########################
#Attack Specific Actions
###########################

mac2ip_convertor "${home_macs_sorted[@]}"
sleep 1
length4=${#protected_macs_converted[@]}

for maccheck in "${home_macs_sorted[@]}"; do

    if [ "$maccheck" == "$router_mac" ]; then

             echo "!Router's Cache is Probably Poisoned! Preparing System to act as the Default Gateway if needed."
             sudo sysctl -w net.ipv4.ip_forward=1 > /dev/null 2>&1
             sudo iptables -t nat -A POSTROUTING -s $victim1_ip -o $interface -j MASQUERADE
             echo
             echo
             echo "--- System is Ready ---"
             break

    fi

done

network_scan "1" "$interface" "${source_macs_sorted[@]}"
sleep 1
length3=${#scanned_ip_array[@]}

#####################
#Shield Deployment
#####################

unified_arpspoof=( "${scanned_ip_array[@]}" "${source_macs_sorted[@]}" )
unified_arpspoof=( "$interface" "$ids_ips_mac" "$victim1_mac" "$router_mac" "$victim1_ip" "$ids_ips_ip" "$default_gateway_ip" "$length3" "${unified_arpspoof[@]}" )

destination_ipcheck "$length4" "arpspoof.sh" "${protected_macs_converted[@]}" "${unified_arpspoof[@]
