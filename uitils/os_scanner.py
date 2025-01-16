import nmap


def analyze_os(target_ip):
    """
    Analyzes the operating system of a given IP address using nmap.

    Args:
        target_ip (str): The IP address to analyze.

    Returns:
        dict: Information about the operating system or an error message.
    """
