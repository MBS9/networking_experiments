g++ main.cpp protocols.cpp -o main
sudo ./main

sudo tcpdump -i tap0 -w output.pcap
ping -I tap0 10.0.0.2

ip route add 10.0.0.1/24 via {ip of computer} dev eth0

sudo sysctl -w net.ipv4.ip_forward=1
