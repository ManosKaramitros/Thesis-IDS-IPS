#!/bin/bash

#Handler For ICMP Redirection Attacks

echo
echo "ICMP Redirect Packet(s) Detected *** Could be Malicious ***"
echo
sleep 6
sudo kill -15 $SNORT_PID
sleep 1

#################################
#Source & Target Identification
#################################

process_flag "redirect" "14" "16" "2" "22"
sleep 1
malicious_ips=("${home_macs_sorted[@]}")

######################################################
#Evasion Countermeasure Filter and Shield Deployment
######################################################

echo
echo "Checking source IP(s) against pre-Configured Network Variables"
echo "and running a Network Scan to sort out the Spoofed IP(s)"
echo
ip_unspoof "${final_source_sorted[@]}"
sleep 1
redirection_source_array=( "$ids_ips_ip" "$default_gateway_ip" )


if [[ ${#not_spoofed_array[@]} -ne 0 ]]; then

   network_scan "2" "$interface" "${not_spoofed_array[@]}" > /dev/null 2>&1
   sleep 1

   if [[ ${#not_tracable[@]} -ne 0 ]]; then

      echo "Unable to pinpoint every spoofed IP with certainty!! All identified source IPs"
      echo "will be utilized moving forward (Excluding pre-Configured spoofed values)"
      echo

      redirection_source_array=( "${redirection_source_array[@]}" "${not_spoofed_array[@]}" )

      destination_ipcheck "$length6" "icmpredirect.sh" "${final_destination_sorted[@]}" "${redirection_source_array[@]}"

   else

      echo "Finished searching. Will utilize Source IP(s): ${reverse_ips[@]}"
      echo

      redirection_source_array=( "${redirection_source_array[@]}" "${scanned_ip_array[@]}" )

      destination_ipcheck "$length6" "icmpredirect.sh" "${final_destination_sorted[@]}" "${redirection_source_array[@]}"

   fi


else

   echo "All Source IP(s) match known network IP(s). Definitely spoofed!"
   echo

   destination_ipcheck "$length6" "icmpredirect.sh" "${final_destination_sorted[@]}" "${redirection_source_array[@]}"

fi
