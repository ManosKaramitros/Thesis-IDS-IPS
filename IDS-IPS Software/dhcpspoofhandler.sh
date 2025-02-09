#!/bin/bash

#Handler For DHCP Spoofing Attacks

################################################################################
#Attack Specific Action - Deploy a Static IP Configuration File to the Victim
################################################################################

create_network_config() {


    interfacedhcp=$1
    victimdhcp=$2
    dns1=$3
    dns2=$4
    router=$5
    systemdhcp=$6
    idssecuredhcp=$7


    cat <<EOL > "01-network-manager-all.yaml.$systemdhcp"
network:
  version: 2
  renderer: networkd
  ethernets:
    $interfacedhcp:
      addresses:
        - $victimdhcp
      nameservers:
        addresses: [$dns1,$dns2]
      routes:
        - to: default
          via: $router

    enp0s9:
      addresses:
        - $idssecuredhcp/24
EOL

    echo "Netplan Configuration file (01-network-manager-all.yaml.$systemdhcp) created for $systemdhcp"
    echo "to pass emergency""static IP address $victimdhcp. Sending it now!"
    echo
    scp 01-network-manager-all.yaml.$systemdhcp $systemdhcp:/home/manos/Desktop > /dev/null
    echo ">> Done. Will use this File later if needed. <<"
    echo
    echo

}

################################################################
#Source & Target Identification - Further Attack Verification
################################################################

echo
echo
echo "*** Detected DHCP Offer Packet From Untrusted Source ***"
echo
echo "--- Potential Rogue DHCP Server ---"

sleep 3
sudo kill -15 $SNORT_PID
sleep 1

process_flag "length" "14" "16" "2" "6" > /dev/null 2>&1
sleep 1
mac2ip_convertor "${home_macs_sorted[@]}" > /dev/null 2>&1
sleep 1
ip_unspoof "${final_source_sorted[@]}" > /dev/null 2>&1
sleep 1

if [ ${#not_spoofed_array[@]} -eq 0 ] && [ ${#protected_macs_converted[@]} -eq 0 ]; then

   echo "False Positive Alert! Exiting.."
   exit 1

fi



length_dhcp=${#protected_macs_converted[@]}

echo
echo
echo "Anilyzing Snort Logs to Extract Crucial Information about the Attack"
echo
echo
echo "Logs Check Came back with the Following:"
echo
echo "Source IP(s): ${not_spoofed_array[@]}"
echo
echo "Destination -- Protected Network -- IP(s): ${protected_macs_converted[@]}"
echo
echo


for macdhcp in "${protected_macs_converted[@]}"; do

    if [ "$macdhcp" == "$victim1_ip" ]; then

        create_network_config "$interface" "$emergency_victim1" "$dns1" "$dns2" "$default_gateway_ip" "victim1" "$victim1_enp0s9_ip"

    else
        echo "DETECTION ERROR!"

    fi

done

#####################
#Shield Deployment
#####################

dhcpspoofing_array=( "$interface" "$default_gateway_ip" "$dns1" "$dns2" "${not_spoofed_array[@]}" )
destination_ipcheck "$length_dhcp" "dhcpspoofing.sh" "${protected_macs_converted[@]}" "${dhcpspoofing_array[@]}"
