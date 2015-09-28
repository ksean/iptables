iptables helper shell script
=====

Usage
====

`./iptables.sh ...*services*`

Supported Services
====

http (80)

https (443)

smtp (25)

dns (53)

ssh (22) -- *limit 4 attempts per IP, per 300s*


Example
====

`./iptables.sh http ssh`

