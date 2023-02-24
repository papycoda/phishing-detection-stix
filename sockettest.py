import socket

url = "www.crestonwood.com"
ip_address = socket.gethostbyname(url)
print(ip_address)
