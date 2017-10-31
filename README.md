iptables helper shell script
=====

Whitelist style iptables firewall configuration script for simple public traffic rules.

## Usage
iptables must be run as a system administrator, this script depends on the `iptables` binary.

`iptables.sh <services>...`

## Supported Services

| Name | Port(s) | Protocol |
| ---- | -------:|:--------:|
| dns | 53 | TCP, UDP |
| ftp | 20, 21 | TCP |
| http | 80 | TCP |
| https | 443 | TCP |
| icmp | n/a | ICMP |
| imap | 143 | TCP |
| imaps | 993 | TCP |
| mysql | 3306 | TCP |
| pop3 | 110 | TCP |
| pop3s | 995 | TCP |
| postgres | 5432 | TCP |
| smtp | 25, 587 | TCP |
| smtps | 465 | TCP |
| ssh | 22 | TCP |


* ssh *limit 4 attempts per IP, per 300s*


## Example
`chmod +x iptables`

`iptables.sh http ssh mysql`