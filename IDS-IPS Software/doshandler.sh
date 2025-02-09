#!/bin/bash

#Handler For DoS Attacks

################################################################################
#Attack Specific Action - Potentially Power Off Protected System Under Attack
################################################################################

dos_function() {


     victims_dos=("$@")

     while true; do

        read -p "** Recommended ** Do you want to shut down the System(s) under Attack? (yes/no): " user_input

        if [ "$user_input" == "yes" ]; then
           echo
           echo

           for victimdos in "${victims_dos[@]}"; do

               if [ "$victimdos" = "$victim1_ip" ]; then

                  system_to_shutdown+=("victim1")

               else

                   echo "Detection Error!!"
                   echo

               fi

           done

           for systemdos in "${system_to_shutdown[@]}"; do

               echo "Shutting Down System $systemdos"
               ssh $systemdos 'sudo shutdown -h now'
               sleep 5

           done

           break

        elif [ "$user_input" == "no" ]; then

             echo
             echo
             echo " ----> Anti-DOS Mode Enabled. Will try to handle the Flood <----"
             echo
             echo "Will block all traffic from/to identified malicious IPs and implement Rate Limiting for the corresponding protocols,"
             echo "to smooth out the bandwidth usage and alleviate the CPU(s). These configurations will help prevent further strain,"
             echo "allowing the Victim System(s) to maintain stability and prevent further resource exhaustion until the attack subsides."
             echo
             echo

             break

        else
                echo
                echo "Invalid input. Please type 'yes' or 'no'."
                echo

        fi


     done

}


echo
echo
echo "*** Denial Of Service (DOS) Attempt ***"
echo

sleep 8
sudo kill -15 $SNORT_PID
sleep 1
counter=""

###########################################################
#Further Classification and Source & Target Identification
###########################################################

if echo "$new_lines" | grep -q "TCP"; then

   counter="TCP"
   echo "--- Type: TCP SYN Flood Attack ---"



elif echo "$new_lines" | grep -q "UDP"; then

     counter="UDP"
     echo "--- Type: UDP Request Flood Attack ---"



elif echo "$new_lines" | grep -q "ICMP"; then

     counter="ICMP"
     echo "--- Type: ICMP Echo - Request Flood Attack ---"


else
     echo "Detection Error! Exiting.."
     exit 1

fi


process_flag "length" "14" "16" "2" "6"
sleep 1
dos_source_array=( "$counter" )
echo
echo
dos_function "${final_destination_sorted[@]}"
sleep 1

#####################################################
#Evasion Countermeasure Filter and Shield Deployment
#####################################################

echo
echo " >>>  Will try to find the original Attacker's IP(s) <<< "
echo
echo
echo "Checking source IP(s) against pre-Configured Network Variables"
echo "and running a Network Scan to sort out the Spoofed IP(s)"
echo

ip_unspoof "${final_source_sorted[@]}"
sleep 1

network_scan "1" "$interface" "${source_macs_sorted[@]}" > /dev/null 2>&1
sleep 1

if [[ ${#not_tracable[@]} -ne 0 ]]; then

   unified_dos_source=( "${scanned_ip_array[@]}" "${not_spoofed_array[@]}" )
   dos_sorted=($(for sorted10 in "${unified_dos_source[@]}"; do echo "${sorted10}"; done |  sort -u))

   if [ "${#dos_sorted[@]}" -ne 0 ]; then

      echo "Unable to pinpoint every spoofed IP with certainty!! All identified source IPs"
      echo "will be utilized moving forward (Excluding pre-Configured spoofed values)"
      echo
      dos_source_array=( "$counter" "${dos_sorted[@]}" )
      destination_ipcheck "$length6" "ddos.sh" "${final_destination_sorted[@]}" "${dos_source_array[@]}"

   else

      echo "Unable to pinpoint any Source IPs!! Only Rate Limiting"
      echo "for the $counter Protocol will be utilized moving forward"
      echo
      destination_ipcheck "$length6" "ddos.sh" "${final_destination_sorted[@]}" "${dos_source_array[@]}"

   fi


else

   echo "Finished Analyzing. Will utilize Malicious IP(s): ${scanned_ip_array[@]}"
   echo
   dos_source_array=( "$counter" "${scanned_ip_array[@]}" )
   destination_ipcheck "$length6" "ddos.sh" "${final_destination_sorted[@]}" "${dos_source_array[@]}"

fi
