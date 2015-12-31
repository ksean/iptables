#!/bin/bash +x

ipt=/sbin/iptables

# Define supported services
DNS=53
HTTP=80
HTTPS=443
IMAP=143
IMAPS=993
MYSQL=3306
POP3=110
POP3S=995
POSTGRES=5432
SMTP=25
SMTPS=465
SSH=22

echo "Flush current rules"
$ipt -F

echo "Set to whitelist mode (default DROP)"
$ipt -P INPUT DROP
$ipt -P OUTPUT DROP
$ipt -P FORWARD DROP

echo "Allow loopback"
$ipt -A INPUT -i lo -j ACCEPT
$ipt -A OUTPUT -o lo -j ACCEPT

echo "Allow established/related inputs"
$ipt -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "Allow established outputs"
$ipt -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT

echo "Drop invalid packets"
$ipt -A INPUT -m conntrack --ctstate INVALID -j DROP

# Incoming rule
# $1    name
# $2    protocol
# $3    port
add_incoming() {
    echo "Adding incoming $1($2:$3) rules"
    $ipt -A INPUT -p $2 --dport $3 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    $ipt -A OUTPUT -p $2 --sport $3 -m conntrack --ctstate ESTABLISHED -j ACCEPT
}

# Outgoing rule
# $1    name
# $2    protocol
# $3    port
add_outgoing() {
    echo "Adding outgoing $1($2:$3) rules"
    $ipt -A OUTPUT -p $2 --dport $3 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
}

for var;
do
    # Handle special rule cases
    if [ $var == "http" ]; then
        add_incoming http tcp $HTTP
        add_outgoing http tcp $HTTP
    elif [ $var == "smtp" ]; then
        add_incoming smtp tcp $SMTP
        $ipt -A OUTPUT -p tcp --dport 587 -j ACCEPT
    elif [ $var == "dns" ]; then
        echo "Adding dns(udp:53) rules"
        $ipt -A OUTPUT -p udp --dport 53 -j ACCEPT
    elif [ $var == "ssh" ]; then
        $ipt -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set --name SSHERS
        $ipt -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 300 --hitcount 4 --name SSHERS -j DROP
        add_incoming ssh tcp $SSH
        add_outgoing ssh tcp $SSH
    else
        # Otherwise default to open incoming via tcp
        uppercase=${var^^}
        add_incoming $var tcp ${!uppercase}
    fi
done

echo "Add logging"
$ipt -N CUSTOMLOG
$ipt -A INPUT -j CUSTOMLOG
$ipt -A OUTPUT -j CUSTOMLOG
$ipt -A FORWARD -j CUSTOMLOG
$ipt -A CUSTOMLOG -m limit --limit 2/min -j LOG --log-prefix "ipt packet: " --log-level 7
$ipt -A CUSTOMLOG -j DROP

exit 0
