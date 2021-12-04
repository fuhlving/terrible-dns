# Terrible DNS
Just a quick horrible DNS client written by me to learn more about the DNS protocol and its network traffic.

Right now you can pass a hostname and a lookup type and it will do its best to recieve and parse the response

Usage:

dns.py google.com a

numeric values can also be used

dns.py google.com 16 # for TXT record lookup.

Result is returned as a dictionary and dumped as json
