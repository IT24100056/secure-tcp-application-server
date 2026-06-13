import socket

s = socket.socket()
s.connect(("127.0.0.1", 50056))

while True:
    msg = input("> ")
    s.send(msg.encode())
    print(s.recv(1024).decode())
