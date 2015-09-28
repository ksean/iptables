#!/bin/bash +x

ipt=/sbin/iptables

echo "Flush current rules"
$ipt -F

echo "Set to whitelist mode (default DROP)"
$ipt -P INPUT DROP
$ipt -P OUTPUT DROP
$ipt -P FORWARD DROP

echo "Allow loopback"
$ipt -A INPUT -i lo -j ACCEPT
$ipt -A OUTPUT -o lo -j ACCEPT

for var;
do
    if [ $var == "http" ]; then
        echo "Adding http(tcp:80) rules"
        $ipt -A INPUT -i eth0 -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
        $ipt -A OUTPUT -o eth0 -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT
    fi

    if [ $var == "https" ]; then
        echo "Adding https(tcp:443) rules"
        $ipt -A INPUT -i eth0 -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
        $ipt -A OUTPUT -o eth0 -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT
    fi

    if [ $var == "smtp" ]; then
        echo "Adding smtp(tcp:25) rules"
        $ipt -A INPUT -i eth0 -p tcp --dport 25 -m state --state NEW,ESTABLISHED -j ACCEPT
        $ipt -A OUTPUT -o eth0 -p tcp --sport 25 -m state --state ESTABLISHED -j ACCEPT
    fi

    if [ $var == "dns" ]; then
        echo "Adding dns(udp:53) rules"
        $ipt -A INPUT -i eth0 -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
        $ipt -A OUTPUT -o eth0 -p udp --sport 53 -m state --state ESTABLISHED -j ACCEPT
    fi

    if [ $var == "ssh" ]; then
        echo "Adding ssh(tcp:22) rules"
        $ipt -A INPUT -i eth0 -p tcp --dport 22 -m state --state NEW -m recent --set --name SSHERS
        $ipt -A INPUT -i eth0 -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 300 --hitcount 4 --name SSHERS -j DROP
        $ipt -A INPUT -i eth0 -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
        $ipt -A OUTPUT -o eth0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT
    fi
done

echo "Add logging"
$ipt -N CUSTOMLOG
$ipt -A INPUT -j CUSTOMLOG
$ipt -A FORWARD -j CUSTOMLOG
$ipt -A CUSTOMLOG -m limit --limit 2/min -j LOG --log-prefix "ipt packet drop: " --log-level 7
$ipt -A CUSTOMLOG -j DROP

exit 0
