#!/bin/bash
sudo bash ./execNS cp4-ns1 tshark -i cp4-veth1-2 -c 100 -w ns1.pcap &
sudo bash ./execNS cp4-ns4 tshark -i cp4-veth4-3 -c 100 -w ns4.pcap &
sudo bash ./execNS cp4-ns1 tc qdisc add dev cp4-veth1-2 root netem delay 200ms loss10%
sudo bash ./execNS cp4-ns1 /lab-netstack-premium-master/lab3/send cp4-veth1-2 > 1.txt &
sudo bash ./execNS cp4-ns2 /lab-netstack-premium-master/lab3/host cp4-veth2-1 cp4-veth2-3 > 2.txt &
sudo bash ./execNS cp4-ns3 /lab-netstack-premium-master/lab3/host cp4-veth3-2 cp4-veth3-4 > 3.txt &
sudo bash ./execNS cp4-ns4 /lab-netstack-premium-master/lab3/recv cp4-veth4-3 > 4.txt &
