#!/bin/bash

#Shield For ICMP Redirection Attacks

ips=$1
shift
router=$1
shift
source_ips_of_redirection=("$@")

###################################################################
#Routing Cache Check and Block Potentially Malicious IP Addresses
###################################################################

echo
echo "--> Checking System's Routing Cache <--"
echo
echo

while IFS= read -r cache_line; do

    destinations=$(echo "$cache_line" | awk -F'[: ]' '{print $1}')
    gateways=$(echo "$cache_line" | awk -F'[: ]' '{print $3}')
    destination_arrays+=("$destinations")
    gateway_array+=("$gateways")

done <<< "$(ip route show cache | grep 'via')"

gateway_array_sorted=($(for gw in "${gateway_array[@]}"; do echo "${gw}"; done | sort -u))

echo "Check Reported back with.."
echo
echo "Destination IP(s) - ${destination_arrays[@]} -"
echo "Are being redirected to Gateway(s): ${gateway_array_sorted[@]}"
echo


for pot_mal_gw in "${gateway_array_sorted[@]}"; do

    if [[ "$pot_mal_gw" != "$ips" && "$pot_mal_gw" != "$router" ]]; then

       malicious_gws+=("$pot_mal_gw")

    fi

done


if [ ${#malicious_gws[@]} -eq 0 ]; then

    echo "---- Traffic is being Redirected to Secure destination IP(s) ---- "
    echo "---- No action needed (Potential Network setup misconfiguration!) ---- "
    echo "Exiting program."
    exit 1
    echo
    echo

else

    sudo iptables -A INPUT -p icmp --icmp-type redirect -j DROP

    for mal_gw in "${malicious_gws[@]}"; do

       echo "-> $mal_gw is not a trusted Gateway address! Blocking it now <-"

       sudo iptables -A INPUT -s $mal_gw -j DROP &&
       sudo iptables -A OUTPUT -d $mal_gw -j DROP &&
       sudo iptables -A FORWARD -d $mal_gw -j DROP &&
       sudo iptables -A FORWARD -s $mal_gw -j DROP

    done
    echo
    echo "Intruder(s) Blocked!"
    echo

fi


for moreip in "${source_ips_of_redirection[@]}"; do

  if [[ ! " ${malicious_gws[@]} " =~ " ${moreip} " ]]; then

    more_ips_array+=("$moreip")

  fi

done


if [ ${#more_ips_array[@]} -ne 0 ]; then

     echo
     echo "Also Blocking the sender's IP(s) as they do not match the malicious"
     echo "IP(s) injected into the system's routing cache."

     for ip_more in "${more_ips_array[@]}"; do

       sudo iptables -A INPUT -s $ip_more -j DROP &&
       sudo iptables -A OUTPUT -d $ip_more -j DROP &&
       sudo iptables -A FORWARD -d $ip_more -j DROP &&
       sudo iptables -A FORWARD -s $ip_more -j DROP

     done
     echo
     echo "Blocked!"
     echo

fi

#############################################################################
#Flush the Routing Cache and Configure the Kernel to Drop Redirect Packets
#############################################################################

echo
echo "### Flushing Routing Cache and Configuring Kernel to Drop ICMP Redirection Packets From all Insecure Sources ###"
echo "Make sure to change this Configuration once the threat is Mitigated"

sudo ip route flush cache
sudo sysctl -w net.ipv4.conf.all.accept_redirects=0 > /dev/null 2>&1 &&
sudo sysctl -w net.ipv4.conf.default.accept_redirects=0 > /dev/null 2>&1 &&
sudo sysctl -w net.ipv4.conf.enp0s3.accept_redirects=0 > /dev/null 2>&1 &&
sudo sysctl -w net.ipv4.conf.lo.accept_redirects=0 > /dev/null 2>&1 &&
sudo sysctl -w net.ipv4.conf.all.secure_redirects=1 > /dev/null 2>&1 &&
sudo sysctl -w net.ipv4.conf.default.secure_redirects=1 > /dev/null 2>&1 &&
sudo sysctl -w net.ipv4.conf.enp0s3.secure_redirects=1 > /dev/null 2>&1 &&
sudo sysctl -w net.ipv4.conf.lo.secure_redirects=1 > /dev/null 2>&1
echo
echo "Done. Traffic will be redirected to the Default Gateway."

