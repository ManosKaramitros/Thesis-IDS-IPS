#!/bin/bash

#Shield For ARP Spoofing Attacks

interface_arpspoof=$1
shift
idsmac_arpspoof=$1
shift
victim1mac_arpspoof=$1
shift
gwmac_arpspoof=$1
shift
victim1_arpspoof=$1
shift
ids_arpspoof=$1
shift
gw_arpspoof=$1
shift
separator_arpspoof=$1
shift
combinedall_arpspoof=("$@")


for ((j=0; j<separator_arpspoof; j++)); do

     ips_arpspoof_array+=("${combinedall_arpspoof[j]}")

done


for ((k=separator_arpspoof; k<${#combinedall_arpspoof[@]}; k++)); do

     macs_arpspoof_array+=("${combinedall_arpspoof[k]}")

done

##############################################################
#Check For Inconsistencies in the ARP Cache Refit If Needed
##############################################################

indexOf() {

        local element="$1"
        shift
        local array=("$@")

        for i in "${!array[@]}"; do
            if [ "${array[$i]}" == "$element" ]; then
                echo "$i"
                return 0
            fi
        done

        echo "-1"

}


check_arp_table() {

    echo
    echo "Checking the System's ARP Cache Based on the Pre - Configured Values.."
    echo
    echo
    current_ip_macs=("$@")

    declare -A expected_macs
    expected_macs["$ids_arpspoof"]="$idsmac_arpspoof"
    expected_macs["$gw_arpspoof"]="$gwmac_arpspoof"
    expected_macs["$victim1_arpspoof"]="$victim1mac_arpspoof"

    ip_array=()
    mac_array=()


    for ((i=0; i<${#current_ip_macs[@]}; i+=2)); do

    ip_without_parentheses=$(echo "${current_ip_macs[i]}" | tr -d '()')
    ip_array+=("$ip_without_parentheses")
    mac_array+=("${current_ip_macs[i+1]}")

    done

    for ip in "${!expected_macs[@]}"; do
          expected_mac="${expected_macs[$ip]}"
          index=$(indexOf "$ip" "${ip_array[@]}")


            if [ "$index" -ne -1 ]; then


                if [ "${mac_array[$index]}" == "$expected_mac" ]; then

                    echo "---- Expected Match found for $ip - ${mac_array[$index]}. No action needed on this Pair ----"
                    echo
                    echo

                else

                    echo "!! Mismatch for $ip: ${mac_array[$index]} (Expected: $expected_mac) !!"
                    mismatch_mac_array+=("${mac_array[$index]}")
                    echo
                    echo

                    if [ "$ip" == "$gw_arpspoof" ]; then

                       ################################################################
                       #Router's Cache is Poisoned - Redirect Traffic through IDS/IPS
                       ################################################################

                       echo "--> Special handling for the Gateway's IP - $ip <---"
                       echo
                       echo "Redirecting all traffic for this machine through the IDS/IPS to avoid the routers Poisoned Cache..."
                       echo
                       sudo iptables -A INPUT -s $gw_arpspoof -j DROP
                       sudo iptables -A OUTPUT -d $gw_arpspoof -j DROP
                       sudo iptables -A FORWARD -s $gw_arpspoof -j DROP
                       sudo iptables -A FORWARD -d $gw_arpspoof -j DROP
                       sudo ip route del default via $gw_arpspoof dev $interface_arpspoof
                       sudo ip route add default via $ids_arpspoof dev $interface_arpspoof
                       echo "Done. Make sure you revert back to normal Network Configurations when the attack is completely mitigated (Network Congestion)"
                       echo
                       echo
                       echo "Refitting the System's ARP Cache Entries"
                       echo
                       sudo ip neigh replace "$ip" lladdr "$expected_mac" dev $interface_arpspoof
                       echo "Malicious Mac for $ip Dropped and Changed back to to $expected_mac"
                       echo
                       echo

                    else

                       echo "Handling $ip..."
                       echo
                       echo "Refitting the System's ARP Cache Entries"
                       echo
                       sudo ip neigh replace "$ip" lladdr "$expected_mac" dev $interface_arpspoof
                       echo "Malicious Mac for $ip Dropped and Changed back to to $expected_mac"
                       echo
                       echo

                    fi
                fi


            else

                   echo "---- IP $ip not found in current ARP Cache. No action needed ----"
                   echo
                   echo
            fi
    done

}

current_ipmacs=($(arp -a -i $interface_arpspoof | awk '/ether/ {print $2, $4}'))
sleep 1
check_arp_table "${current_ipmacs[@]}"

###########################################
#Block the Malicious IP and MAC Addresses
###########################################

if [ "${#ips_arpspoof_array[@]}" -ne 0 ]; then

     echo "Blocking known Intruders IP(s).."
     echo

     for intruderspotip in "${ips_arpspoof_array[@]}"; do

          sudo iptables -A INPUT -s "$intruderspotip" -j DROP
          sudo iptables -A OUTPUT -d "$intruderspotip" -j DROP
          sudo iptables -A FORWARD -s "$intruderspotip" -j DROP
          sudo iptables -A FORWARD -d "$intruderspotip" -j DROP

     done

           echo "IP(s) Blocked"
           echo
           echo

fi

final_malicious=("${mismatch_mac_array[@]}" "${macs_arpspoof_array[@]}")
final_malicious_sorted=($(printf "%s\n" "${final_malicious[@]}" | sort -u))

echo "Blocking known  Intruder's Mac Address..."

for maliciousmacsfinal in "${final_malicious_sorted[@]}"; do

   sudo arptables -A INPUT --src-mac "$maliciousmacsfinal" -j DROP
   sudo arptables -A OUTPUT --dst-mac "$maliciousmacsfinal" -j DROP

done

echo
echo "MAC(s) Blocked."
echo
echo
echo
