from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, DNS, Raw, wrpcap

# Initialize a list to store captured packets
captured_packets = []

# Packet handler function
def packet_handler(packet):
    captured_packets.append(packet)  # Save the packet to the list

    # Check if the packet has an IP layer
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        print(f"\n[+] New Packet: {ip_src} -> {ip_dst} (Protocol: {protocol})")

        # If the packet has a TCP layer
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"TCP Packet: {ip_src}:{src_port} -> {ip_dst}:{dst_port}")
            print(f"Flags: {packet[TCP].flags}")
            if Raw in packet:
                print(f"Payload: {packet[Raw].load}")

        # If the packet has a UDP layer
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"UDP Packet: {ip_src}:{src_port} -> {ip_dst}:{dst_port}")
            if Raw in packet:
                print(f"Payload: {packet[Raw].load}")

        # If the packet has an ICMP layer
        elif ICMP in packet:
            print(f"ICMP Packet: {ip_src} -> {ip_dst} (Type: {packet[ICMP].type})")

    # Check for ARP packets
    if ARP in packet:
        print(f"ARP Packet: {packet[ARP].psrc} -> {packet[ARP].pdst} (Operation: {packet[ARP].op})")

    # Check for DNS packets
    if DNS in packet:
        print(f"DNS Packet: {packet[IP].src} -> {packet[IP].dst} (Query: {packet[DNS].qd.qname})")

# Function to start packet sniffing
def start_sniffing(interface=None, count=0, bpf_filter=None):
    print(f"[*] Starting packet capture on interface {interface}...")
    sniff(iface=interface, prn=packet_handler, count=count, filter=bpf_filter)

# Function to save captured packets to a file
def save_packets(filename):
    wrpcap(filename, captured_packets)
    print(f"[*] Saved {len(captured_packets)} packets to {filename}")

if __name__ == "__main__":
    interface = input("Enter the interface to sniff on (e.g., eth0, wlan0): ")
    packet_count = int(input("Enter the number of packets to capture (0 for infinite): "))
    
    # Implementing filtering based on IP addresses, ports, or protocols
    filter_ip_src = input("Enter the source IP to filter by (leave blank for no filter): ")
    filter_ip_dst = input("Enter the destination IP to filter by (leave blank for no filter): ")
    filter_port_src = input("Enter the source port to filter by (leave blank for no filter): ")
    filter_port_dst = input("Enter the destination port to filter by (leave blank for no filter): ")
    filter_protocol = input("Enter the protocol to filter by (tcp, udp, icmp, arp, dns): ").lower()

    # Building the BPF filter string
    bpf_filter = ""
    if filter_ip_src:
        bpf_filter += f"src host {filter_ip_src} "
    if filter_ip_dst:
        bpf_filter += f"dst host {filter_ip_dst} "
    if filter_port_src:
        bpf_filter += f"src port {filter_port_src} "
    if filter_port_dst:
        bpf_filter += f"dst port {filter_port_dst} "
    if filter_protocol:
        bpf_filter += f"and {filter_protocol} "

    bpf_filter = bpf_filter.strip()
    print(f"[*] Using BPF filter: {bpf_filter}")

    start_sniffing(interface, packet_count, bpf_filter)

    # Option to save captured packets
    save_option = input("Do you want to save the captured packets to a file? (y/n): ").lower()
    if save_option == 'y':
        filename = input("Enter the filename to save the packets (e.g., captured_packets.pcap): ")
        save_packets(filename)
