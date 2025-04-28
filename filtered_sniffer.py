from scapy.all import sniff, wrpcap

packets = sniff(filter="tcp port 80", count=50)
wrpcap("http_traffic.pcap", packets)