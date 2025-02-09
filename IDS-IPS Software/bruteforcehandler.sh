#!/bin/bash

#Handler For Brute Force Attacks

##############################
#Further Attack Verification
##############################

first_line=$(echo "$new_lines" | head -n 1)
sleep 8

file_path_bruteforce="/var/log/snort/alert"
line_number=$(grep -nF "$first_line" "$file_path_bruteforce" | cut -d: -f1)
final_lines_bruteforce=$(awk "NR > $line_number" "$file_path_bruteforce" | wc -l)

if [ "$final_lines_bruteforce" -gt 3 ]; then

   echo
   echo " ^^^^ SSH Password Authentication Bruteforce Attempt ^^^^ "
   echo
   sudo kill -15 $SNORT_PID
   sleep 1

else

   echo "Detection Error: Insufficient lines for Bruteforce SSH Password Authentication detection."
   echo "Exiting program."
   exit 1

fi

########################################################
#Source & Target Identification and Shield Deployment
########################################################

process_flag "SSH" "14" "16" "2" "6"
sleep 1
destination_ipcheck "$length6" "bruteforce.sh" "${final_destination_sorted[@]}" "${final_source_sorted[@]}"
