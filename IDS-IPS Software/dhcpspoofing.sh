#!/bin/bash

#Shield For DHCP Spoofing Attacks

interfacedhcp=$1
shift
gateway_dhcp=$1
shift
dns1_dhcp=$1
shift
dns2_dhcp=$1
shift
dhcp_malservers=("$@")

##########################################
#Check The Default GWs and DNS Servers
##########################################

mal_gws=()
maldns_servers=()

echo
echo "--- Checking the Gateway and DNS Servers IPs ---"
echo


while IFS= read -r gatewayline; do


  defaultgw=$(echo "$gatewayline" | awk '{print $3}')

  defaultgw_array+=("$defaultgw")

done < <(ip route | grep '^default')


for gw in "${defaultgw_array[@]}"; do

  if [[ "$gw" != "$gateway_dhcp" ]]; then

    echo "!! Untrusted Gateway Found: $gw"
    echo
    mal_gws+=("$gw")

  fi

done

if [ "${#mal_gws[@]}" -eq 0 ]; then

   echo
   echo "<< Check came back with No Untrusted Gateways >>"
   echo

fi


while IFS= read -r linedns; do

  if [[ "$linedns" != "$dns1_dhcp" && "$linedns" != "$dns2_dhcp" ]]; then

  echo "!! Untrusted DNS Server Found: $linedns"
  echo
  maldns_servers+=("$linedns")

  fi

done < <(sudo resolvectl status $interfacedhcp | grep "DNS Servers" | awk '{for(i=3;i<=NF;i++) print $i}')


if [ "${#maldns_servers[@]}" -eq 0 ]; then

   echo
   echo "<< Check came back with No Untrusted DNS Servers >>"
   echo

fi

#########################################
#Apply the Static IP Configuration File
#########################################

echo
while true; do

    read -p "Do you want to apply the Static IP Configuration file that was created earlier for this System? (yes/no): " user_input

    if [ "$user_input" = "yes" ]; then

        echo
        echo "Flushing all Malicious Configurations on the Interface First.."
        sudo ip addr flush dev $interfacedhcp &&
        sudo dhclient -r > /dev/null 2>&1 &&
        sudo rm /var/lib/dhcp/dhclient.leases &&
        echo
        echo "Done! Static IP is redy to be Applied"
        echo
        echo
        break

    elif [ "$user_input" = "no" ]; then

         echo
         echo "No Action Taken! Exiting.."
         break
         exit 1

    else

        echo
        echo "Invalid input. Please type 'yes' or 'no'."
        echo

    fi

done

filename=$(ls | grep "01-network-manager-all.yaml") &&
filename_cut=$(echo "$filename" | cut -d '.' -f 1,2) &&
sudo mv /home/manos/Desktop/$filename /home/manos/Desktop/$filename_cut
cd &&
sudo mv /home/manos/Desktop/$filename_cut /etc/netplan


#######################################
#Block all the Malicious IP Addresses
#######################################

echo "Blocking all Malicious Identified IPs.."

mal_ipsdhcp=( "${mal_gws[@]}" "${maldns_servers[@]}" "${dhcp_malservers[@]}" )
mal_ips_sorted=($(for dhcpspoofip in "${mal_ipsdhcp[@]}"; do echo "${dhcpspoofip}"; done | sort -u))

for mal in "${mal_ips_sorted[@]}"; do

sudo iptables -A INPUT -s $mal -j DROP &&
sudo iptables -A OUTPUT -d $mal -j DROP &&
sudo iptables -A FORWARD -d $mal -j DROP &&
sudo iptables -A FORWARD -s $mal -j DROP

done

echo
echo "Blocked!"
echo
echo
echo "Applying new Neplan Network Configurations and Exiting"
echo
echo "Make sure to enable DHCP Services (If Needed) when the attack is completely Mitigated!"
sudo netplan apply > /dev/null 2>&1
