import socket
from scapy.all import ARP, Ether, srp
import nmap
from attack_engine import *

class STROT_CLI:
    def __init__(self, *args, **kwargs) -> None:
        '''
            STROT - CLI initializer
        '''
        print("-"*20, "\nGetting the Private IP of Host...")
        self.privateIP = self.get_privateIp()
        self.privateIP_range = self.get_privateIP_range()
        print("Private IP of Host Machine:", self.privateIP)

        print("-"*20, "\nScanning the network...")
        self.devices_in_network = self.network_scanner()

        if self.devices_in_network:
            print("\nDevices found in the network:")
            print("IP Address\t\tMAC Address")
            print("-----------------------------------------")
            for device in self.devices_in_network:
                print(f"{device['ip']}\t\t{device['mac']}")
        else:
            print("No devices found.")

        self.target_ip = ""
        while not self.verify_ip(self.target_ip):
            self.target_ip = input("-"*20 + "\nSelect the node ip to be scanned: ")
        os_scan_result = self.os_scanner(self.target_ip)    
        if os_scan_result['status'] == "success":
            print("\nOperating System Analysis:")
            for match in os_scan_result['os_matches']:
                print(f"Name: {match['name']}\nAccuracy: {match['accuracy']}%\n")
                break
        else:
            print(f"Error: {os_scan_result['message']}")

        service_scan_result = self.service_scan(self.target_ip)

        if service_scan_result['status'] == "success":
            print("\nService Scan Results:")
            print("Port\tState\tName\tProduct\tVersion")
            print("----------------------------------------------------------")
            for service in service_scan_result['services']:
                print(f"{service['port']}\t{service['state']}\t{service['name']}\t{service['product']}\t{service['version']}")
        else:
            print(f"Error: {service_scan_result['message']}")

        version_scan_result = self.version_scan(self.target_ip)

        if version_scan_result['status'] == "success":
            print("\nVersion Scan Results:")
            print("Port\tState\tName\tProduct\tVersion")
            print("----------------------------------------------------------")
            for service in version_scan_result['services']:
                print(f"{service['port']}\t{service['state']}\t{service['name']}\t{service['product']}\t{service['version']}")
        else:
            print(f"Error: {version_scan_result['message']}")

    @staticmethod
    def get_privateIp() -> str:
        '''
            get_privateIP is a staticmethod that returns 
            the Private IP address of the host machine
        '''
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # Connect to an external server (Google DNS)
        ip_address = s.getsockname()[0]  # Get the IP address of the machine
        s.close()

        return ip_address
    
    @staticmethod
    def verify_ip(ip_address) -> bool:
        try:
            if len(ip_address.split(".")) == 4:
                for i in ip_address.split("."):
                    int(i)
                return True
            else:
                return False
        except:
            return False
        
    def get_privateIP_range(self) -> str:
        range = ".".join(self.privateIP.split(".")[:-1]) + ".0/24"
        return range

    def network_scanner(self) -> list:
        """
        Scans the network for active devices within the specified IP range.

        Args:
            ip_range (str): The IP range to scan, e.g., "192.168.1.1/24".

        Returns:
            list: A list of dictionaries containing IP and MAC addresses of active devices.
        """
        # Create an ARP request packet
        ip_range = self.privateIP_range
        arp_request = ARP(pdst=ip_range)
        # Create an Ethernet frame to wrap the ARP request
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        # Send the packet and capture responses
        responses, _ = srp(packet, timeout=2, verbose=False)

        # Parse the responses to extract IP and MAC addresses
        devices = []
        for response in responses:
            devices.append({
                "ip": response[1].psrc,
                "mac": response[1].hwsrc
            })

        return devices
    
    def os_scanner(self, target_ip) -> str:
        """
        Analyzes the operating system of a given IP address using nmap.

        Args:
            target_ip (str): The IP address to analyze.

        Returns:
            dict: Information about the operating system or an error message.
        """
        # Create an Nmap PortScanner object
        nm = nmap.PortScanner()

        try:
            print("-"*20, f"\nScanning IP: {target_ip} for OS detection...")
            # Run the OS detection scan
            scan_result = nm.scan(hosts=target_ip, arguments="-O", timeout=30)
            
            # Check if the scan was successful
            if 'osmatch' in scan_result['scan'][target_ip]:
                os_matches = scan_result['scan'][target_ip]['osmatch']
                return {
                    "status": "success",
                    "os_matches": os_matches
                }
            else:
                return {
                    "status": "error",
                    "message": "No OS information could be determined."
                }

        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
        
    def service_scan(self, target_ip):
        """
        Runs an Nmap service scan on the given IP address.

        Args:
            target_ip (str): The IP address to scan.

        Returns:
            dict: Information about the services or an error message.
        """
        # Create an Nmap PortScanner object
        nm = nmap.PortScanner()

        try:
            print("-"*20, f"\nScanning IP: {target_ip} for services...")
            # Run the service scan
            # scan_result = nm.scan(hosts=target_ip, arguments="-sV", timeout=1000)
            scan_result = nm.scan(hosts=target_ip, arguments="-r", timeout=1000)

            # Check if the scan was successful
            if target_ip in scan_result['scan']:
                services = []
                for port in scan_result['scan'][target_ip].get('tcp', {}):
                    port_info = scan_result['scan'][target_ip]['tcp'][port]
                    services.append({
                        "port": port,
                        "state": port_info.get('state', 'unknown'),
                        "name": port_info.get('name', 'unknown'),
                        "product": port_info.get('product', 'unknown'),
                        "version": port_info.get('version', 'unknown')
                    })
                return {
                    "status": "success",
                    "services": services
                }
            else:
                return {
                    "status": "error",
                    "message": "No services could be determined."
                }

        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }
            
    def version_scan(self, target_ip):
        """
        Runs an Nmap service scan on the given IP address.

        Args:
            target_ip (str): The IP address to scan.

        Returns:
            dict: Information about the services or an error message.
        """
        # Create an Nmap PortScanner object
        nm = nmap.PortScanner()

        try:
            print("-"*20, f"\nScanning IP: {target_ip} for services...")
            # Run the service scan
            scan_result = nm.scan(hosts=target_ip, arguments="-sV", timeout=1000)
            # scan_result = nm.scan(hosts=target_ip, arguments="-r", timeout=1000)

            # Check if the scan was successful
            if target_ip in scan_result['scan']:
                services = []
                for port in scan_result['scan'][target_ip].get('tcp', {}):
                    port_info = scan_result['scan'][target_ip]['tcp'][port]
                    services.append({
                        "port": port,
                        "state": port_info.get('state', 'unknown'),
                        "name": port_info.get('name', 'unknown'),
                        "product": port_info.get('product', 'unknown'),
                        "version": port_info.get('version', 'unknown')
                    })
                return {
                    "status": "success",
                    "services": services
                }
            else:
                return {
                    "status": "error",
                    "message": "No services could be determined."
                }

        except Exception as e:
            return {
                "status": "error",
                "message": str(e)
            }


if __name__ == "__main__":
    obj = STROT_CLI()
