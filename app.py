import eel
import random
eel.init("frontend")

previous_ip_location = {}


@eel.expose
def network_devices():
    return ["192.168.1.1", "192.168.1.211", "192.168.200.1"]


if __name__ == "__main__":
    eel.start("index.html")
