from scapy.all import *

#@staticmethod
def packet_send(payload, src, dst, sport, dport, flag, mode):
    packet = IP(dst=dst, src=src)/TCP(sport=sport, dport=dport, flags = flag)/Raw(payload)
    return mode(packet, iface='lo')
    # we can use sendp to choose different network interface
    #sendp(packet, iface="en0")
