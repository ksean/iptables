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

echo "Allow established/related inputs"
$ipt -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

echo "Allow established outputs"
$ipt -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT

echo "Drop invalid packets"
$ipt -A INPUT -m conntrack --ctstate INVALID -j DROP

for var;
do
    if [ $var == "http" ]; then
        echo "Adding incoming http(tcp:80) rules"
        $ipt -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
        $ipt -A OUTPUT -p tcp --sport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT
        echo "Adding outgoing http(tcp:80) rules"
        $ipt -A OUTPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    fi

    if [ $var == "https" ]; then
        echo "Adding incoming https(tcp:443) rules"
        $ipt -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
        $ipt -A OUTPUT -p tcp --sport 443 -m conntrack --ctstate ESTABLISHED -j ACCEPT
    fi

    if [ $var == "smtp" ]; then
        echo "Adding smtp(tcp:25,587) rules"
        $ipt -A INPUT -p tcp --dport 25 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
        $ipt -A OUTPUT -p tcp --dport 25 -j ACCEPT
        $ipt -A OUTPUT -p tcp --dport 587 -j ACCEPT
    fi

    if [ $var == "smtps" ]; then
        echo "Adding smtp(tcp:465) rules"
        $ipt -A INPUT -p tcp --dport 465 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
        $ipt -A OUTPUT -p tcp --dport 465 -j ACCEPT
    fi

    if [ $var == "dns" ]; then
        echo "Adding dns(udp:53) rules"
        $ipt -A OUTPUT -p udp --dport 53 -j ACCEPT
    fi

    if [ $var == "ssh" ]; then
        echo "Adding incoming ssh(tcp:22) rules"
        $ipt -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set --name SSHERS
        $ipt -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 300 --hitcount 4 --name SSHERS -j DROP
        $ipt -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
        $ipt -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT
        echo "Adding outgoing ssh(tcp:22) rules"
        $ipt -A OUTPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
    fi

    if [ $var == "postgres" ]; then
        echo "Adding postgres(tcp:5432) rules"
        $ipt -A INPUT -p tcp --dport 5432 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
        $ipt -A OUTPUT -p tcp --sport 5432 -m conntrack --ctstate ESTABLISHED -j ACCEPT
    fi

    if [ $var == "mysql" ]; then
        echo "Adding mysql(tcp:3306) rules"
        $ipt -A INPUT -p tcp --dport 3306 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
        $ipt -A OUTPUT -p tcp --sport 3306 -m conntrack --ctstate ESTABLISHED -j ACCEPT
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
