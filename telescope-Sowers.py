import collections
import datetime
import dpkt 
import matplotlib.pyplot as plt 
import numpy as np 
import socket
import sys

fd = open("telescope.pcap", "rb")   # open file
pcap = dpkt.pcap.Reader(fd)         # read pcap data

pkts = 0                            # 1.
start_time = 0                      # 2.
end_time = 0                        # 2.
dsts = set()
total_bytes_transferred = 0         # 2.
num_ip_packets = 0                  # 3.
protos = dict()                     # 5.
pktsizes = [0]*31                   # 6. 31 bins of 50 B packet sizes
synAckDsts = dict()                 # 10.
tcp_ports = dict()                  # 12.
unique_ports = collections.defaultdict(set)     # 13.
cdf_ports = []                      # 13.
just_23_2323 = []                   # 14.

print "Analyzing pcap file... (this could take up to 10 minutes)"

# For each packet in the pcap, process the contents
for timestamp, buf in pcap:         # for each packet in the caputre
  pkts+=1                           # 1. count the packets
  if pkts == 1:
    start_time = timestamp          # 2. get the start time of the trace
  if timestamp > end_time:    
    end_time = timestamp            # 2. get the end time of the trace

  # Unpack the Ethernet frame (mac src/dst, ethertype)
  eth = dpkt.ethernet.Ethernet(buf)
  if eth.type == 0x800: 		        # ethernet protocol for IPv4
    # Unpack the data within the Ethernet frame (the IP packet)
    # Pull out src, dst, length, fragment info, TTL, Protocol
    ip = eth.data                   # IP object
    ascii_dst = socket.inet_ntoa(ip.dst)         # translate the IP address to ascii
    ascii_src = socket.inet_ntoa(ip.src)         # translate the IP address to ascii
    dsts.add(ascii_dst)             # add destination addresses to set
    num_ip_packets += 1             # 3. keep track of total # IPv4 packets

    bytes_transferred = ip.len                      # 2. get num bytes in packet
    total_bytes_transferred += bytes_transferred    # 2. track total bytes in trace

    # 5. create a dictionary of protocols and their quantities
    if ip.p not in protos: 	        # if we have not seen the protocol,
      protos[ip.p] = 0              # add it to our dictionary
    protos[ip.p]+=1                 # increment the quantity

    # 6. create a list of packet sizes
    binned_value = ip.len/50        # create histo bins of size 50
    pktsizes[binned_value]+=1       # increment the value for the corresponding bin

    if ip.p == dpkt.ip.IP_PROTO_TCP:        # if protocol equals TCP
      tcp = ip.data                         # TCP object
      if pkts == 18798595:
        continue

      # Packet info: IP src, IP dst, length, TTL
      #              ip.src, ip.dst, ip.len, ip.ttl

      # 10. If there are TCP flags and SYN and ACK are present (not zero)
      if (tcp.flags & dpkt.tcp.TH_SYN != 0 and tcp.flags & dpkt.tcp.TH_ACK != 0):
        if ascii_src not in synAckDsts:               # if the IP is not in our dict
          synAckDsts[ascii_src] = 0                   # add it
        synAckDsts[ascii_src] += 1                    # increment
      # 13. How many unique dest ports did each host attempt connections with?
      elif (tcp.flags & dpkt.tcp.TH_SYN != 0):        # otherwise (no ACK), if TCP SYN packet 
        unique_ports[ascii_src].add(tcp.dport)        # add the TCP DST port to the set for that IP

      # 12. Identifying TCP protocols
      if tcp.dport not in tcp_ports:                  # if the TCP dst port is not in our dict
        tcp_ports[tcp.dport] = 0                      # add it
      tcp_ports[tcp.dport] += 1                       # increment

# 13. How many unique dest ports did each host attempt connections with?
for item in unique_ports: 		                        # for each IP/port set, 
  cdf_ports.append(len(unique_ports[item])) 	        # add the length of the set to a list
  # print type(unique_ports[item])
  
  # 14. How many IP sources initiated connections to both TCP port 23 and 2323, but no others?
  if unique_ports[item] == set([23, 2323]):           # If the unique ports are exactly 23 and 2323,
    # print item, unique_ports[item]
    just_23_2323.append(item)                         # Create a list with those IPs

# 13.
unique_tcp_port_dist = collections.Counter(cdf_ports) 
ordered_dict = collections.OrderedDict(sorted(unique_tcp_port_dist.items()))
sorted_list_quantities = [0]*1800

for k,v in ordered_dict.iteritems():
  sorted_list_quantities[k] = v

cdf = np.cumsum(sorted_list_quantities, dtype=float)                              
new_cdf = [x / cdf[-1] for x in cdf]


print "\n#1. Num pkts: %s" % pkts                                 # 1.

duration = end_time - start_time                                # 2.
print "#2. Average traffic rate: %2.3f bits/sec" % (total_bytes_transferred * 8 / duration) # 2.

print "#3. Number of IPv4 packets: %d \n" % num_ip_packets      # 3. 

print "#5."
for protocol in protos:                                        
  print ("Protocol: %4s, Quantity: %8d" % (protocol, protos[protocol]))

# print "\n#6. Packet sizes (in bins of 50): ", pktsizes          # 6.

# 10.
print "\n#10. Highest rate DoS attack:\nIP: %s, Quantity: %d" % (sorted(synAckDsts, key=synAckDsts.get)[-1], synAckDsts[sorted(synAckDsts, key=synAckDsts.get)[-1]])
# 11.
print "#11. DoS attack rate: ~%d packets/sec" % (synAckDsts[sorted(synAckDsts, key=synAckDsts.get)[-1]] * 16777216 / duration)

# 12.
print "\n#12. Highest probed TCP ports:"
for key in sorted(tcp_ports, key=tcp_ports.get)[-5:]:
  print "Port: %5d," % key, "Quantity: %7d" % tcp_ports[key]

# 13.
# print "\n#13. List of # of unique ports per host:"
# for key in unique_tcp_port_dist:
#   print "# unique ports: %4d," % key, "Quantity: %6d" % unique_tcp_port_dist[key]

# 14. 
print "\n#14: IP sources that initiated connections to ports 23 and 2323 only: %d" % len(just_23_2323)

# 13.
plt.plot(range(1800), new_cdf)
plt.show()




