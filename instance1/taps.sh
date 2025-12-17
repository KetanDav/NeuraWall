#!/bin/bash

# Create 4 TAP interfaces: tap0, tap1, tap2, tap3
# Assign IPs but DO NOT configure any gateway or routing

declare -A IPS=(
  [tap0]="192.168.100.2/24"
  [tap1]="192.168.100.3/24"
  [tap2]="192.168.200.4/24"
  [tap3]="192.168.200.5/24"
)

for IFACE in tap0 tap1 tap2 tap3; do
    echo "Creating $IFACE..."

    sudo ip tuntap add dev "$IFACE" mode tap
    sudo ip link set dev "$IFACE" up
    sudo ip addr add "${IPS[$IFACE]}" dev "$IFACE"

    echo "$IFACE configured with IP ${IPS[$IFACE]}"
done

echo "All TAP interfaces created successfully (NO gateway added)."
