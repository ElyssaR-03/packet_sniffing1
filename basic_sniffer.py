from scapy.all import sniff

def simple_sniffer(packet):
    print(packet.summary())

sniff(prn=simple_sniffer, count=10)