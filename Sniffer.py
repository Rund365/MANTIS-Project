from scapy.all import sniff, Raw
from scapy.packet import Packet
import time
from scapy.layers.l2 import PacketList
from Reassembler import SessionFileReassembler
import Loopbackdict

stop_sniffing_flag = False

def start_sniffing(filters, packet_count, captured_packets:PacketList,interface_to_be_used,loopback_flag):
    reassembler_for_sniffer= SessionFileReassembler()
    """Starts the sniffing process."""
    global stop_sniffing_flag
    stop_sniffing_flag = False

    def stop_sniffer(packet):
        return stop_sniffing_flag

    def process_packet(packet: Packet):
        captured_packets.append(packet)
        if packet.haslayer('TCP') and packet.haslayer(Raw):
            reassembler_for_sniffer.process_packet(packet)
    #sniff(prn=process_packet, filter=filters, count=packet_count, stop_filter=stop_sniffer, iface='lo0')
    sniff(prn=process_packet, filter=filters, count=packet_count, stop_filter=stop_sniffer, iface=interface_to_be_used)

def stop_sniffing():
    """Stops the sniffing process."""
    global stop_sniffing_flag
    stop_sniffing_flag = True