#!/bin/bash

#Handler For Nmap Scans

echo
echo "Recon activity -- Potential Nmap Scan Detected!"
echo

sleep 6
sudo kill -15 $SNORT_PID
sleep 1


first_line=$(echo "$new_lines" | head -n 1)
scantype=0

###########################################################
#Further Classification and Source & Target Identification
###########################################################

if echo "$first_line" |  grep -q "Stealth/Full Scan"; then

   echo "Type: Nmap Stealth/Full Scan. Check the Log File for further Information."
   process_flag "Flags [R.]" "16" "14" "6" "16"
   ((scantype++))



elif echo "$first_line" |  grep -q "Fin"; then

     echo "Type: Nmap Fin Scan. Check the Log File for further Information."
     process_flag "Flags [F]" "14" "16" "2" "14"



elif echo "$first_line" |  grep -q "Null"; then

     echo "Type: Nmap Null Scan. Check the Log File for further Information."
     process_flag "Flags [none]" "14" "16" "2" "14"



elif echo "$first_line" |  grep -q "Xmas"; then

     echo "Type: Nmap Xmas Scan. Check the Log File for further Information."
     process_flag "Flags [FPU]" "14" "16" "2" "14"



else

     echo "Detection Error."
fi

#####################################################
#Evasion Countermeasure Filter and Shield Deployment
#####################################################

nmap_source_array=( "$ids_ips_ip" "$ids_enp0s9_ip" "$victim1_enp0s9_ip" "$victim1_ip" "$default_gateway_ip" )


if (( length2 > length1 )); then

    echo "Snort logs analysis also shows fewer source MACs compared to source IPs."
    echo "This indicates potential spoofed decoy IP addresses in the attack."
    echo "Will try to find the original Attacker's IP(s)"
    network_scan "1" "$interface" "${source_macs_sorted[@]}"
    echo

    if [[ ${#not_tracable[@]} -ne 0 ]]; then

       echo "System was unable to trace all malicious MACs back to the corresponding IPs. All identified"
       echo "source IPs will be utilized moving forward (Excluding known pre-Configured spoofed values)"
       echo
       ip_unspoof "${final_source_sorted[@]}"
       sleep 1
       nmap_source_array=( "${nmap_source_array[@]}" "${not_spoofed_array[@]}" )
       destination_ipcheck "$length6" "nmap.sh" "${final_destination_sorted[@]}" "${nmap_source_array[@]}"


    else

       nmap_source_array=( "${nmap_source_array[@]}" "${scanned_ip_array[@]}" )
       echo
       destination_ipcheck "$length6" "nmap.sh" "${final_destination_sorted[@]}" "${nmap_source_array[@]}"


    fi


elif (( length1 == length2 )); then

      nmap_source_array=( "${nmap_source_array[@]}" "${final_source_sorted[@]}" )
      echo
      destination_ipcheck "$length6" "nmap.sh" "${final_destination_sorted[@]}" "${nmap_source_array[@]}"

fi
