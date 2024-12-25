# NetFeatureXtract
An efficient system for traffic feature extraction utilizing the eBPF and XDP.

# Step to run

## Install Dependencies

On a Linux machine - used Ubunto version 24.04.1:

- Install Git and clone the NetFeatureXtract repo:
`sudo apt install git-all`
`git clone https://github.com/geinsfeldt/NetFeatureXtract.git`

- Install Make:
`sudo apt install make`

- Install packages:
`sudo apt install clang llvm libelf-dev libpcap-dev build-essential libc6-dev-i386`

- Install additional kernel headers dependency:
`sudo apt install linux-headers-$(uname -r)`

- Install uthash:
`sudo apt install uthash-dev`

- Install extra tools:
`sudo apt install linux-tools-common linux-tools-generic`
`sudo apt install tcpdump`

## Executing NetFeatureXtract

- First run command make inside the project folder. It will compile and create 2 new files one: xdp_user and xdp_kern_feature_extract.o.
`make`

- Second execute the create_test_interface.sh that will create two interfaces for testing test0 (packets sender) and test1 (packets receiver).
`sudo ./create_test_interface.sh`

- Third run the userspace code informing the interface where the xdp code will attach.
`sudo xdp_user test1`

This version of userspace code do a infinite while loop printing the results of flows features in the flow map each second. Each time the code is run, it resets the maps and start as new.

## Testing

### Install Dependencies

- Install python 3:
`sudo apt install python3`

- Install python packages:
`sudo apt install python3-scapy`
`sudo apt install python3-psutil`

- Enable kernel to collect BPF statistics:
`sysctl -w kernel.bpf_stats_enabled=1`

### First Experiment

This experiment calculate and print the average execution time and standard deviation for the xdp program given number of flows, number of packets per second, duration and iterations.

Run example from Experiment1 folder:
`sudo ./test.sh`

To vary the features is necessary to change variable FEATURE_MASK in xdp_user.c code and compile again with make command and run the compiled code.

### Second Experiment

This experiment register the CPU and Memory usage in percentage given packets sent to interface with number, interval, destination ip, payload length, if it is ipv6, if it is udp and if it should use multi threads.

Run example from Experiment2 folder:
`sudo python3 packet_simulator.py test1 -n 10 -i 0.2 -d 192.168.100.2 -l 50 --udp --multi`

## Auxiliar commands

- Check if the created packets are being received by destination interface.
`sudo tcpdump -i test1 -n`

- Check prints inside ebpf/xdp code.
`sudo cat /sys/kernel/debug/tracing/trace_pipe`

- Remove xdp code from the interface.
`sudo ip link set dev test1 xdp off`






