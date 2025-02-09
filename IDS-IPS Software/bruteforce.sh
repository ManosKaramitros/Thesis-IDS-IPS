#!/bin/bash

#Shield For SSH Authentication Bruteforce Attacks

source_ips_br=("$@")
SSHD_CONFIG="/etc/ssh/sshd_config"

###############################################
#Check Potential Present or Past Connections
###############################################

for ip in "${source_ips_br[@]}"; do

  echo
  echo "---> Processing Malicious IP: $ip <---"
  echo

  pts=$(who | grep "$ip" | awk '{print $2}')

  if [ -z "$pts" ]; then

     echo
     echo "Attacker is not currently connected to the Machine via SSH..."

  else

     echo
     echo "(!) The Attacker is conneted to the Machine via SSH now (!)"
     echo
     echo "Killing the malicious connection.."
     pid=$(ps aux | grep "sshd" | grep "$pts" | awk '{print $2}')
     sudo kill -9 $pid
     echo
     echo "Done. Attacker Kicked off the System!"
     echo

  fi

done

######################################################
#Disable Password Authentication For SSH Connections
######################################################

echo
echo
echo "--- Disabling Password Authentication For SSH Connections ---"
sudo sed -i 's/^#*PasswordAuthentication .*/PasswordAuthentication no/' $SSHD_CONFIG
sudo systemctl restart sshd
sleep 1

if grep -q "^PasswordAuthentication no" "$SSHD_CONFIG"; then

    echo
    echo "Password authentication has been successfully disabled for SSH."
    echo
    echo

else

    echo
    echo "Failed to disable password authentication for SSH."
    echo
    echo

fi

##################################
#Block the Malicious IP Addresses
##################################

echo "--- Blocking Intruders IP(s) ---"

for malipbr in "${source_ips_br[@]}"; do

  sudo iptables -A INPUT -s $malipbr -j DROP &&
  sudo iptables -A OUTPUT -d $malipbr -j DROP &&
  sudo iptables -A FORWARD -d $malipbr -j DROP &&
  sudo iptables -A FORWARD -s $malipbr -j DROP

done

echo
echo "Intruder Blocked. Make sure you enable SSH Password Authentication (if needed) after the Attack is completely Mitigated."
