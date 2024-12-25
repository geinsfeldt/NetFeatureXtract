import random
import subprocess
import re
import statistics
from scapy.all import *

def generate_random_ip():
    """Generate a random IPv4 address in the 192.168.0.0/16 range"""
    return f"192.168.{random.randint(0, 255)}.{random.randint(1, 254)}"

def generate_random_mac():
    """Generate a random MAC address"""
    return "02:42:ac:11:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255))

def generate_high_rate_multiflow_traffic(num_flows, num_packets, duration):
    """
    Generate high-rate traffic with multiple flows
    """
    iface = "test0"
    flows = []
    
    # Generate different flows
    for _ in range(num_flows):
        flow = {
            'src_mac': generate_random_mac(),
            'dst_mac': generate_random_mac(),
            'src_ip': generate_random_ip(),
            'dst_ip': generate_random_ip(),
            'src_port': random.randint(1024, 65535),
            'dst_port': random.randint(1024, 65535)
        }
        flows.append(flow)
    
    # Create packet list with different flows
    packets = []
    for flow in flows:
        pkt = (Ether(src=flow['src_mac'], dst=flow['dst_mac']) /
               IP(src=flow['src_ip'], dst=flow['dst_ip']) /
               UDP(sport=flow['src_port'], dport=flow['dst_port']) /
               b"High rate packet")
        packets.append(pkt)
    
    print(f"Sending high-rate packets with {num_flows} different flows from {iface}...")
    # Randomly select packets from different flows
    
    sendpfast(packets, iface=iface, pps=num_packets, loop=(num_packets * duration) / num_flows)


def get_xdp_stats():
    """
    Executes bpftool to retrieve XDP performance statistics.
    Returns a dictionary with `run_cnt` and `run_time_ns`.
    """
    try:
        result = subprocess.run(["bpftool", "prog", "show"], 
                                capture_output=True, 
                                text=True, 
                                check=True)
        output = result.stdout
        
        # Split the output into lines and locate the XDP program section
        for line in output.splitlines():
            if "xdp" in line and "run_time_ns" in line:  # Locate the correct XDP program line
                # Extract `run_cnt` and `run_time_ns` using regex
                run_time_match = re.search(r"run_time_ns\s+(\d+)", line)
                run_cnt_match = re.search(r"run_cnt\s+(\d+)", line)
                
                if run_time_match and run_cnt_match:
                    return {
                        "run_cnt": int(run_cnt_match.group(1)),
                        "run_time_ns": int(run_time_match.group(1))
                    }
        
        # If no stats are found
        raise ValueError("No XDP program stats found in bpftool output")
    
    except subprocess.CalledProcessError as e:
        print("Error running bpftool:", e.stderr)
        return None

def monitor_xdp_performance(num_flows, num_packets, duration, iterations):
    """
    Monitors XDP performance over multiple iterations of a specific duration (in seconds).
    Tracks deltas for `run_cnt` and `run_time_ns` to avoid accumulated values skewing results.
    """
    results = []
    prev_stats = {"run_cnt": 0, "run_time_ns": 0}

    for i in range(iterations):
        print(f"\n=== Iteration {i+1}/{iterations} ===")
        
        # Step 1: Generate traffic for the specified duration
        generate_high_rate_multiflow_traffic(num_flows, num_packets, duration)
        
        # Step 2: Collect XDP statistics
        current_stats = get_xdp_stats()
        if current_stats:
            # Calculate deltas for this iteration
            delta_run_cnt = current_stats["run_cnt"] - prev_stats["run_cnt"]
            delta_run_time_ns = current_stats["run_time_ns"] - prev_stats["run_time_ns"]

            # Update previous stats for the next iteration
            prev_stats = current_stats

            # Calculate average time per execution for this iteration
            avg_time_ns = delta_run_time_ns / delta_run_cnt if delta_run_cnt > 0 else 0
            results.append(avg_time_ns)
            print(f"Run Count: {delta_run_cnt}, Run Time (ns): {delta_run_time_ns}, Avg Time (ns): {avg_time_ns:.2f}")
        else:
            print("Failed to retrieve XDP stats.")
            return None

    # Calculate average performance metrics
    avg_ns = statistics.mean(results)
    stdev_ns = statistics.stdev(results) if len(results) > 1 else 0
    print("\n=== XDP Performance Summary ===")
    print(f"Average Execution Time (ns): {avg_ns:.2f}")
    print(f"Standard Deviation (ns): {stdev_ns:.2f}")
    return avg_ns, stdev_ns

if __name__ == "__main__":
    monitor_xdp_performance(num_flows=60, num_packets=18000, duration=10, iterations=30)
