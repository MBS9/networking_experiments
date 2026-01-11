# C++ implementation of some network protocols for personal education

## Preparing

To compile:
```shell
g++ main.cpp protocols.cpp -o main
```

To make packet routing possible for outbound packets (run this on the computer where you run this program):
```shell
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -A FORWARD -j ACCEPT

## The below only for NAT
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

To make packet routing for inbound packets (assuming no NAT is used, run this on the computer sending packets):
(replace the ip addresses with the correct value for your specific setup)
```shell
## For windows (assuming you are on the same network as 10.0.0.2):
netsh interface ipv4 add neighbors "Local Area Connection" 10.0.0.2 00-15-5d-05-ab-06

## For linux (assuming you are not on the same network as 10.0.0.2; I didn't test this as I only used windows):
ip route add 10.0.0.0/24 via {ip of computer} dev eth0
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
