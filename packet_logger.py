import csv
from scapy.all import sniff

def log_to_csv(packet):
    if packet.haslayer("IP"):
        with open("log.csv", "a", newline='') as f:
            writer = csv.writer(f)
            writer.writerow([packet.time, packet["IP"].src, packet["IP"].dst, packet.proto])

sniff(filter="ip", prn=log_to_csv, count=20)