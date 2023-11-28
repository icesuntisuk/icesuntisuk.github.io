from scapy.all import *

# Set the destination IP address
dest_ip = "10.0.0.1"

# Create an HTTP GET request
get_request = HTTPRequest(
    Host=dest_ip,
    Method="GET",
    Path="/",
    Version="HTTP/1.1",
)

# Create a TCP packet with the HTTP GET request as the payload
tcp_packet = TCP(
    dport=80,
    flags="PA",
    seq=1,
    ack=1,
    window=65535,
) / get_request

# Create an IP packet with the TCP packet as the payload
ip_packet = IP(
    dst=dest_ip,
) / tcp_packet

# Send the IP packet
send(ip_packet)