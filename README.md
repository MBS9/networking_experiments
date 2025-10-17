g++ main.cpp protocols.cpp -o main
sudo ./main

ip route add 10.0.0.1/24 via {ip of computer} dev eth0

sudo sysctl -w net.ipv4.ip_forward=1
