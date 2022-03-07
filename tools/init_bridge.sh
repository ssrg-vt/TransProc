#!/bin/bash

## Check parameters
if  [ "$#" -ne 1 ]; then
	echo "Usage: $0 <NIC name>"
	exit 1
fi

ip link show | grep $1:  &> /dev/null
nic=$(echo $?)
if [ $nic -ne 0 ]; then
	echo "Usage: $0 <NIC name> (e.g., $0 eth0)"
	exit 1
fi

#Create the bridge
sudo ip link add br0 type bridge

#Add an ip address to the bridge
#sudo ip addr add 172.20.0.1/16 dev br0
sudo ip addr add 10.20.10.1/24 dev br0

#Start the interface
sudo ip link set br0 up

#sudo dnsmasq --interface=br0 --bind-interfaces --dhcp-range=172.20.0.2,172.20.255.254

#sudo modprobe tun

#Disable iptables from network bridges
sudo sh -c "echo 0  | tee /proc/sys/net/bridge/bridge-nf-call-iptables"

#Set up ip forwarding
sudo sysctl net.ipv4.ip_forward=1
sudo sysctl net.ipv6.conf.default.forwarding=1
sudo sysctl net.ipv6.conf.all.forwarding=1

# netfilter cleanup
#sudo iptables --flush
#sudo iptables -t nat -F
#sudo iptables -X
#sudo iptables -Z
#sudo iptables -P INPUT ACCEPT
#sudo iptables -P OUTPUT ACCEPT
#sudo iptables -P FORWARD ACCEPT

#Iptables for internet
sudo iptables -t nat -A POSTROUTING -o $1 -s 10.20.10.0/24 -j MASQUERADE
sudo iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i tap0 -o $1 -j ACCEPT
sudo iptables -A FORWARD -i tap1 -o $1 -j ACCEPT
