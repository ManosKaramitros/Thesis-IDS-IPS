  GNU nano 6.2                                                                                                                                                                                                                                                                                                                                                                                                                                                            nmap.sh                                                                                                                                                                                                                                                                                                                                                                                                                                                                     
#!/bin/bash

#Shield For Nmap Scans

ids_nmap=$1
shift
ids_e9_nmap=$1
shift
victim1_e9_nmap=$1
shift
victim1_nmap=$1
shift
gw_nmap=$1
shift
nmap_source_array=("$@")


victim1="$victim1_nmap"

trusted_sources=( "$victim1_nmap" "$ids_nmap" "$ids_e9_nmap" "$victim1_e9_nmap" "$gw_nmap" )

flag=0

##################################
#Block the Malicious IP Addresses
##################################

if [ "${#nmap_source_array[@]}" -ne 0 ]; then

   echo
   echo
   echo "Banning Intruders IP(s)"
   echo

   for source_ip_nmap in "${nmap_source_array[@]}"; do

       sudo iptables -A INPUT -s "$source_ip_nmap" -j DROP &&
       sudo iptables -A OUTPUT -d "$source_ip_nmap" -j DROP &&
       sudo iptables -A FORWARD -d "$source_ip_nmap" -j DROP &&
       sudo iptables -A FORWARD -s "$source_ip_nmap" -j DROP

   done

   echo "Banned Successfully"
   echo
   echo

else
     echo "NO IP(s) TO BAN?"

fi


###########################################
#Open Port(s) Check and Filter Application
###########################################

apply_filter() {

    local port=$1
    local service=$2


    echo "-> Found Port $port (Service $service) Open <-"
    echo

    while true; do

        read -p "Do you want to filter this port for trusted connections only? (yes/no): " user_input

        if [ "$user_input" = "yes" ]; then

            echo
            echo "Applying filter on port $port..."
            echo

            for trusted_source in "${trusted_sources[@]}"; do
                sudo iptables -A INPUT -p tcp -s "$trusted_source" --dport "$port" -j ACCEPT
                sudo iptables -A OUTPUT -p tcp -d "$trusted_source" --sport "$port" -j ACCEPT
            done

            sudo iptables -A INPUT -p tcp --dport "$port" -j DROP
            sudo iptables -A OUTPUT -p tcp --sport "$port" -j DROP &&

            echo "Done. Make sure to Drop the Filter once the Threat is Mitigated"
            echo
            echo

            break

        elif [ "$user_input" = "no" ]; then

            echo
            echo "No action taken. Port stays unfiltered for potentially malicious Connections..."
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


echo "Searching for some Default Open Ports on the Machine..."
echo

sleep 1

nmap_output=$(sudo nmap -sT $victim1)

if echo "$nmap_output" | grep -q '22/tcp'; then

    flag=$((flag + 1))

    apply_filter 22 SSH

fi


if echo "$nmap_output" | grep -q '80/tcp'; then

    flag=$((flag + 1))

    apply_filter 80 HTTP

fi


if [ "$flag" -eq 0 ]; then

  echo
  echo "Found 0 Usually Open Ports."

fi

