#!/bin/bash

INTERFACE="test1"

sudo ip link set dev $INTERFACE xdp off

# Test with XDP
echo "Testing with XDP"
sudo ../xdp_user $INTERFACE
sudo python3 monitor.py & wait

echo "Testing completed."