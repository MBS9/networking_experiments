# C++ implementation of some network protocols

## Preparing

To compile:
```shell
g++ main.cpp protocols.cpp -o main
```

To make packet routing possible for outbound connections:
```shell
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -A FORWARD -j ACCEPT

## The below only for NAT
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

To make packet routing for inbound packets (assuming no NAT is used, run this on the computer sending packets):
```shell
## For windows:
netsh interface ipv4 add neighbors "Local Area Connection" 192.168.1.224 00-15-5d-05-ab-06

## For linux:
ip route add 10.0.0.1/24 via {ip of computer} dev eth0
```

## Running

```shell
sudo ./main
```

To capture packets:
```shell
sudo tcpdump -i tap0 -w output.pcap
```

To test ping:
```shell
ping -I tap0 10.0.0.2
```
