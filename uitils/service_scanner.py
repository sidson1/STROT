import nmap
def service_scan(target_ip):
    """
    Runs an Nmap service scan on the given IP address.

    Args:
        target_ip (str): The IP address to scan.

    Returns:
        dict: Information about the services or an error message.
    """