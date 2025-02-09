#!/bin/bash

##############################
#Set up the Network Variables
##############################

ids_ips_ip="10.0.2.4"
ids_enp0s9_ip="10.2.2.7"
victim1_enp0s9_ip="10.2.2.8"
victim1_ip="10.0.2.5"
default_gateway_ip="10.0.2.1"

home_network="10.0.2.0/24"

interface="enp0s3"

router_mac="52:54:00:12:35:00"
victim1_mac="08:00:27:c0:f8:21"
ids_ips_mac="08:00:27:98:39:56"

dns1="192.168.1.1"
dns2="1.1.1.1"

emergency_victim1="10.0.2.50/24"

dhcp_server="10.0.2.3"

##############################
#Functions
##############################

center_text() {

    local term_width=$(tput cols)

    local text="$1"

    local bold_colored_text="\e[1;33m$text\e[0m"

    local text_length=${#text}

    local padding=$(( (term_width - text_length) / 2 ))

    printf "%${padding}s" ""

    echo -e "$bold_colored_text"

}



process_flag() {

    flag=$1
    attack_src_col=$2
    attack_dst_col=$3
    mal_mac_col=$4
    home_mac_col=$5

    echo
    echo
    echo "Anilyzing Snort Logs to Extract Crucial Information about the Attack"


    latest_log_file=$(ls -t /var/log/snort/snort.log.* | head -n 1) > /dev/null 2>&1
    tcpdump_output=$(sudo tcpdump -e -r "$latest_log_file" 2>/dev/null | grep -F "$flag" 2>/dev/null)


    while IFS= read -r attackline; do

           atckipsrc=$(echo "$attackline" | awk -v src_col=$attack_src_col '{print $src_col}' | cut -d':' -f1)
           atckipdest=$(echo "$attackline" | awk -v dst_col=$attack_dst_col '{print $dst_col}' | cut -d':' -f1)
           atckmacsrc=$(echo "$attackline" | awk -v malmac_col=$mal_mac_col '{print $malmac_col}')
           homemacdst=$(echo "$attackline" | awk -v homemac_col=$home_mac_col '{print $homemac_col}')

           source_ips_of_attack_unsorted+=("$atckipsrc")
           destination_ips_of_attack_unsorted+=("$atckipdest")
           source_macs_of_attack_unsorted+=("$atckmacsrc")
           home_macs_of_attack_unsorted+=("$homemacdst")

     done <<< "$tcpdump_output"

     source_ips_sorted=($(for sorted1 in "${source_ips_of_attack_unsorted[@]}"; do echo "${sorted1}"; done |  sort -u))
     destination_ips_sorted=($(for sorted2 in "${destination_ips_of_attack_unsorted[@]}"; do echo "${sorted2}"; done |  sort -u))
     source_macs_sorted=($(for sorted3 in "${source_macs_of_attack_unsorted[@]}"; do echo "${sorted3}"; done |  sort -u))
     home_macs_sorted=($(for sorted4 in "${home_macs_of_attack_unsorted[@]}"; do echo "${sorted4}"; done |  sort -u))
     length5=${#source_ips_sorted[@]}
     ipcombination_array_unconverted=("${source_ips_sorted[@]}" "${destination_ips_sorted[@]}")


     for ipconversion in "${ipcombination_array_unconverted[@]}"; do

         if [[ "$ipconversion" =~ ^_gateway ]]; then

            ipcombination_array+=("$default_gateway_ip")

         elif [[ "$ipconversion" =~ ^manos-VirtualBox ]]; then

              ipcombination_array+=("$ids_ips_ip")

         else
              ipcombination_array+=("$ipconversion")

         fi


     done

     for converted in "${ipcombination_array[@]}"; do

         final_array_combined+=("$(echo "$converted" | cut -d'.' -f1-4)")

     done

     for ((l=0; l<length5; l++)); do

         final_source_unsorted+=("${final_array_combined[l]}")

     done


     for ((m=length5; m<${#final_array_combined[@]}; m++)); do

         final_destination_unsorted+=("${final_array_combined[m]}")

     done

     final_source_sorted=($(for sorted6 in "${final_source_unsorted[@]}"; do echo "${sorted6}"; done |  sort -u))
     final_destination_sorted=($(for sorted7 in "${final_destination_unsorted[@]}"; do echo "${sorted7}"; done |  sort -u))
     length1=${#source_macs_sorted[@]}
     length2=${#final_source_sorted[@]}
     length6=${#final_destination_sorted[@]}

     echo
     echo
     echo "Logs Check Came back with the Following:"
     echo
     echo "Source IP(s): ${final_source_sorted[@]}"
     echo
     echo "Destination -- Protected Network -- IP(s): ${final_destination_sorted[@]}"
     echo

}



network_scan() {

    reverse_mode=$1
    shift
    interfacetype=$1
    shift
    mac_addresses_toscan=("$@")

    echo
    echo
    echo "Running a Scan to Map the Attacker's MAC(s) back to the Corresponding IP(s)"
    interface=$interfacetype
    network=$home_network
    not_traced=0

    for malmac in "${mac_addresses_toscan[@]}"; do

        scan_result=$(sudo arp-scan -I "$interface" "$network" | grep -i "$malmac" | awk -v field="$reverse_mode" '{print $field}')

        if [[ -z "$scan_result" ]]; then

             not_tracable+=("$malmac")
             ((not_traced++))

        else
               scanned_ip_array+=("$scan_result")
               reverse_ips+=("$malmac")

        fi

    done

    if [ "${#scanned_ip_array[@]}" -ne 0 ]; then

        echo
        echo "-> Finished Analyzing. Scan Results Indicate Malicious IP(s): ${scanned_ip_array[@]} <-"
        echo

    else
        echo
        echo "-> Scan Came Back with Nothing! <-"
        echo

    fi

    if [[ "$not_traced" -ne 0 ]]; then

       echo "-> Was not Able to Trace MAC(s): ${not_tracable[@]} <-"
       echo

    fi

}



destination_ipcheck() {

    separator=$1
    shift
    script_name=$1
    shift
    combinedall_array=("$@")

    for ((i=0; i<separator; i++)); do

        victims_array+=("${combinedall_array[i]}")

    done

    for ((i=separator; i<${#combinedall_array[@]}; i++)); do

        scriptspecific_array+=("${combinedall_array[i]}")

    done

    for protip in "${victims_array[@]}"; do

        if [ "$protip" = "$victim1_ip" ]; then

           attacked_machines+=("victim1")

        elif [ "$protip" = "$default_gateway_ip" ]; then

            attacked_machines+=("Router")

        elif [ "$protip" = "$ids_ips_ip" ]; then

            attacked_machines+=("IDS-IPS")

        else
              echo
              echo " !!  Detection Error For $protip !!"
              echo

        fi

    done

    echo "-- Protected-Netowrk Machine(s) Under Attack: ${attacked_machines[@]} --"
    echo
    echo
    echo
    echo

    for system in "${attacked_machines[@]}"; do

       if [[ "$system" != "Router" && "$system" != "IDS-IPS" ]]; then

          center_text "For $system..." &&
          (
          scp $script_name $system:/home/manos/Desktop > /dev/null  &&
          echo -e "\n" &&
          center_text "Security Script (Shield) Installed Successfully to the Target System" &&
          ssh -t $system "cd /home/manos/Desktop && ./$script_name ${scriptspecific_array[@]}"
          )

       fi

    done

}



mac2ip_convertor() {

      protected_macs_notconverted=("$@")

      for macconvert in "${protected_macs_notconverted[@]}"; do

         if [ "$macconvert" = "$victim1_mac" ]; then

            protected_macs_converted+=("$victim1_ip")

         elif [ "$macconvert" = "$router_mac" ]; then

               protected_macs_converted+=("$default_gateway_ip")

         elif [ "$macconvert" = "$ids_ips_mac" ]; then

              protected_macs_converted+=("$ids_ips_ip")

         else
              echo "ERROR! Nothing Found For $macconvert"
         fi

      done

}



ip_unspoof() {

    ips_to_unspoof=("$@")

    for ipspoofed in "${ips_to_unspoof[@]}"; do

        if [[ "$ipspoofed" != "$ids_ips_ip" && \
              "$ipspoofed" != "$default_gateway_ip" && \
              "$ipspoofed" != "$dhcp_server" && \
              "$ipspoofed" != "$victim1_ip" ]]; then

                  not_spoofed_array+=("$ipspoofed")

        fi

    done

    length7=${#not_spoofed_array[@]}

}

##############################
#Snort NIDS Start Up
##############################

echo
echo
center_text "Starting Up..."
echo -e "\n\n"
sleep 2

gnome-terminal --title="snort" -- bash -c "cd && sudo snort -q -l /var/log/snort -i $interface -A fast -c /etc/snort/snort.conf2 -b; exec bash"

while true; do

    SNORT_PID=$(pidof snort)

    if [[ -n "$SNORT_PID" ]]; then

        window_id=$(wmctrl -l | grep "manos@manos-VirtualBox: ~/Desktop" | awk '{print $1}')

        wmctrl -i -a $window_id

        break

    fi

    sleep 1

done

sleep 1
center_text "-- Defensive System Initialized -- Waiting for Snort to Generate Alerts --"
echo
echo

######################################
#Attack Verification & Classification
######################################

file_path="/var/log/snort/alert"

initial_size=$(wc -l < "$file_path")

sudo inotifywait -e modify "$file_path" > /dev/null 2>&1
sleep 1

while true; do

    INOTIFYWAIT_PID=$(pidof inotfywait)

    if [[ -z "$INOTIFYWAIT_PID" ]]; then

       timestamp=$(date +"%d/%m %H:%M:%S")
       echo "Snort Detected Malicious Traffic at $timestamp" &&
       sleep 2
       new_lines=$(awk "NR > $initial_size" "$file_path")

       break

    fi

    sleep 1

done


if echo "$new_lines" |  grep -q "Nmap"; then

   source nmaphandler.sh


elif echo "$new_lines" |  grep -q "ARP"; then

   source arpspoofhandler.sh


elif  echo "$new_lines" |  grep -q "SSH Attempt"; then

   source bruteforcehandler.sh


elif echo "$new_lines" |  grep -q "Redirection"; then

   source redirectionhandler.sh


elif echo "$new_lines" |  grep -q "DDOS"; then

   source doshandler.sh


elif echo "$new_lines" |  grep -q "DHCP SPOOFING."; then

   source dhcpspoofhandler.sh


fi


