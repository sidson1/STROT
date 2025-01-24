from scapy.all import ARP, Ether, srp

def scan_network(ip_range):
    """
    Scans the network for active devices within the specified IP range.

    Args:
        ip_range (str): The IP range to scan, e.g., "192.168.1.1/24".

    Returns:
        list: A list of dictionaries containing IP and MAC addresses of active devices.
    """
    # Create an ARP request packet
    arp_request = ARP(pdst=ip_range)
    # Create an Ethernet frame to wrap the ARP request