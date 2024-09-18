import scapy.all as scapy
import argparse
from tabulate import tabulate
import ipaddress

def get_arguments():
    parser = argparse.ArgumentParser(description="Network Scanner")
    parser.add_argument("-r", "--range", dest="network_ip", required=True, help="IP range to scan (e.g., 192.168.1.0/24)")
    parser.add_argument("-i", "--interface", dest="interface", help="Specify the interface to use (optional)")
    args = parser.parse_args()
    
    try:
        ipaddress.ip_network(args.network_ip)
    except ValueError:
        parser.error("Invalid IP range. Please specify a valid network IP range (e.g., 192.168.1.0/24).")
    
    return args

def scan(network_ip, interface=None):
    arp_request = scapy.ARP(pdst=network_ip)
    arp_broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = arp_broadcast / arp_request
    if interface:
        answered_list = scapy.srp(arp_request_broadcast, iface=interface, timeout=1, verbose=False)[0]
    else:
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients = []
    for element in answered_list:
        client_dict = {"IP": element[1].psrc, "MAC": element[1].hwsrc}
        clients.append(client_dict)
    return clients

def print_result(clients):
    if clients:
        print(tabulate(clients, headers="keys", tablefmt="pretty"))
    else:
        print("No devices found on the network.")

if __name__ == "__main__":
    try:
        args = get_arguments()
        scan_result = scan(args.network_ip, args.interface)
        print_result(scan_result)
    except PermissionError:
        print("You need to run the script with sudo or root privileges.")
    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    except Exception as e:
        print(f"An error occurred: {e}")
