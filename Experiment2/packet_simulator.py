import csv
import threading
import psutil
import scapy.all as scapy
import time
import argparse
import random
import ipaddress

def monitor_performance(duration=60):
    with open("xdp_stress_test_results.csv", 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(["Time", "CPU Usage (%)", "Memory Usage (%)"])
        
        start_time = time.time()
        while time.time() - start_time < duration:
            cpu_percent = psutil.cpu_percent(interval=0.1)
            memory_percent = psutil.virtual_memory().percent
            csvwriter.writerow([time.time() - start_time, cpu_percent, memory_percent])

def generate_random_payload(length):
    return ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=length))

def ipv4_to_ipv6(ipv4_address):
    # Convert IPv4 to integer
    ipv4_int = int(ipaddress.IPv4Address(ipv4_address))
    # Create IPv6 address in the format ::ffff:IPv4
    ipv6 = ipaddress.IPv6Address(0xffff00000000000000000000 | ipv4_int)
    return str(ipv6)

def create_packet(dst_ip, use_ipv6, use_udp, payload):
    if use_ipv6:
        ip_layer = scapy.IPv6(dst=dst_ip, src=ipv4_to_ipv6("192.168.100.1"))
    else:
        ip_layer = scapy.IP(dst=dst_ip, src="192.168.100.1")
    
    if use_udp:
        transport_layer = scapy.UDP(dport=9999)
    else:
        transport_layer = scapy.TCP(dport=80)
    
    return scapy.Ether()/ip_layer/transport_layer/payload

def send_packets_thread(packets, interface):
    scapy.sendp(packets, iface=interface)

def send_packets(interface, num_packets, interval, dst_ip, payload_length, use_ipv6, use_udp, multi):
    if use_ipv6:
        dst_ip = ipv4_to_ipv6(dst_ip)
    
    if (multi) :

        packets = []
        for i in range(num_packets): 
            payload = generate_random_payload(payload_length)
            packet = create_packet(dst_ip, use_ipv6, use_udp, payload)
            packets.append(packet)

        monitor_thread = threading.Thread(target=monitor_performance)

        monitor_thread.start()

        scapy.sendp(packets, iface=interface)

        monitor_thread.join()

    else :
        for i in range(num_packets):
            payload = generate_random_payload(payload_length)
            packet = create_packet(dst_ip, use_ipv6, use_udp, payload)
            
            scapy.sendp(packet, iface=interface)
            
            ip_version = "IPv6" if use_ipv6 else "IPv4"
            protocol = "UDP" if use_udp else "TCP"
            print(f"Sent packet {i+1}/{num_packets} to {dst_ip} ({ip_version}, {protocol}), length: {len(packet)} bytes")
            
            time.sleep(interval)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Send simulated packets to an interface")
    parser.add_argument("interface", help="The network interface to send packets to")
    parser.add_argument("-n", "--num_packets", type=int, default=10, help="Number of packets to send")
    parser.add_argument("-i", "--interval", type=float, default=1.0, help="Interval between packets in seconds")
    parser.add_argument("-d", "--dst_ip", default="192.168.100.1", help="Destination IP address (always in IPv4 format)")
    parser.add_argument("-l", "--payload_length", type=int, default=64, help="Length of random payload in bytes")
    parser.add_argument("--ipv6", action="store_true", help="Use IPv6 instead of IPv4")
    parser.add_argument("--udp", action="store_true", help="Use UDP instead of TCP")
    parser.add_argument("--multi", action="store_true", help="Send all packet at once")
    
    args = parser.parse_args()
    
    send_packets(args.interface, args.num_packets, args.interval, args.dst_ip, args.payload_length, args.ipv6, args.udp, args.multi)