import subprocess
from scapy.all import sniff, Raw
from scapy.packet import Packet
from Reassembler import SessionFileReassembler

stop_sniffing_flag = False

def apply_tc_limit(interface, port, bandwidth_kbps):
    """Apply bandwidth limit using tc netem on loopback or HTB on real interfaces."""
    remove_tc_limit(interface, port)  # Clear old rules first

    try:
        bandwidth_kbit = bandwidth_kbps  # Convert to Kbit

        if interface == "lo":
            # ✅ Use `netem` for loopback
            subprocess.run(f"sudo tc qdisc replace dev {interface} root netem rate {bandwidth_kbit}kbit", shell=True, check=True)
            print(f"✅ Applied loopback bandwidth limit: {bandwidth_kbps} Kbps on port {port} via {interface}")
        else:
            # ✅ Use `htb` for physical interfaces
            subprocess.run(f"sudo tc qdisc replace dev {interface} root handle 1: htb default 10", shell=True, check=True)
            subprocess.run(f"sudo tc class add dev {interface} parent 1: classid 1:1 htb rate {bandwidth_kbit}kbit ceil {bandwidth_kbit}kbit", shell=True, check=True)
            subprocess.run(f"sudo tc class add dev {interface} parent 1:1 classid 1:{port} htb rate {bandwidth_kbit}kbit ceil {bandwidth_kbit}kbit", shell=True, check=True)
            subprocess.run(f"sudo tc filter add dev {interface} protocol ip parent 1: prio 1 u32 match ip dport {port} 0xffff flowid 1:{port}", shell=True, check=True)
            print(f"✅ Applied bandwidth limit: {bandwidth_kbps} Kbps on port {port} via {interface}")

        return True
    except subprocess.CalledProcessError as e:
        print(f"⚠️ Failed to apply tc limit: {e}")
        return False

def remove_tc_limit(interface, port):
    """Remove the traffic control (tc) limit for both loopback and physical interfaces."""
    try:
        if interface == "lo":
            subprocess.run(f"sudo tc qdisc del dev {interface} root", shell=True, check=False)
            print(f"✅ Removed loopback bandwidth limit on port {port} via {interface}")
        else:
            subprocess.run(f"sudo tc class del dev {interface} classid 1:{port}", shell=True, check=False)
            subprocess.run(f"sudo tc filter del dev {interface} parent 1: protocol ip prio 1", shell=True, check=False)
            print(f"✅ Removed bandwidth limit on port {port} via {interface}")

        return True
    except subprocess.CalledProcessError as e:
        print(f"⚠️ Failed to remove tc limit: {e}")
        return False

def start_sniffing(filters, packet_count, captured_packets, interface_to_be_used, port=None, bandwidth_kbps=0):
    """Starts packet sniffing with optional tc bandwidth limiting."""
    reassembler_for_sniffer = SessionFileReassembler()
    global stop_sniffing_flag
    stop_sniffing_flag = False

    # Apply bandwidth limit if port and bandwidth are specified
    if port and bandwidth_kbps > 0:
        success = apply_tc_limit(port, bandwidth_kbps)
        if not success:
            print(f"⚠️ Warning: Failed to apply tc limit on port {port}")

    def stop_sniffer(packet):
        return stop_sniffing_flag

    def process_packet(packet: Packet):
        captured_packets.append(packet)
        if packet.haslayer('TCP') and packet.haslayer(Raw):
            reassembler_for_sniffer.process_packet(packet)

    if interface_to_be_used:
        print(f"📡 Starting packet sniffing on {interface_to_be_used} with filters: {filters}")
        sniff(prn=process_packet, filter=filters, count=packet_count, stop_filter=stop_sniffer, iface=interface_to_be_used)
    else:
        print(f"📡 Starting packet sniffing on all interfaces with filters: {filters}")
        sniff(prn=process_packet, filter=filters, count=packet_count, stop_filter=stop_sniffer)

    # Remove bandwidth limit after sniffing stops
    if port:
        remove_tc_limit(port)

def stop_sniffing(port=None):
    """Stops sniffing and removes traffic control limit if applied."""
    global stop_sniffing_flag
    stop_sniffing_flag = True

    if port:
        remove_tc_limit(port)
