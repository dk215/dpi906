# dpi906
Assignment for DPI906 using osquery and scapy

scapy is used purely as a packet sniffer.

Each packet IP is sent to Virustotal and returns malicious if it has >50 average malicious detection rate.

All confirmed malicious IPs are checked for in osquery tables and their related process is killed.
