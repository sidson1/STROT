from pymsfrpc import msfrpc
ip = "your server ip"
user = "your username"
passwd = "your passwd"
c = msfrpc.Client(ip,user,passwd)
output = c.get_version()
print(output[b"version"])
print(output[b"ruby"])