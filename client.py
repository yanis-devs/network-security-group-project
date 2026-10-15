
import hashlib
import ssl
import socket
import sys

HOST = "localhost"
PORT = 8080

username = input("username: ").strip()
password = input("password: ").strip()
hashed_password = hashlib.sha256(password.encode("utf-8")).hexdigest()


def send_request(request):
    plain_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    secure_socket = context.wrap_socket(plain_socket, server_hostname=HOST)

    try:
        secure_socket.connect((HOST, PORT))
        secure_socket.sendall(request.encode("utf-8"))
        reply = b""
        while True:
            chunk = secure_socket.recv(4096)
            if not chunk:
                break
            reply += chunk
    finally:
        secure_socket.close()

    return reply.decode("utf-8", errors="replace")


# Step 1: plain request, no Authorization header
first_request = (
    "GET / HTTP/1.1\r\n"
    f"Host: {HOST}:{PORT}\r\n"
    "Connection: close\r\n"
    "\r\n"
)

text = send_request(first_request)

parts = text.split("\r\n\r\n", 1)
if len(parts) < 2:
    print("Malformed reply:")
    print(text)
    sys.exit(1)

head, body = parts
print(head)

lines = head.split("\r\n")
status_line = lines[0]
header_lines = lines[1:]

parts2 = status_line.split(" ", 2)
_, status_code_string, _ = parts2

status_code = int(status_code_string)

if(status_code == 200):
    print(body)

headers = {}

for line in lines[1:]:
    name, value = line.split(":", 1)
    headers[name.lower()] = value.strip()


print(headers.get("www-authenticate"))

if(status_code == 401):
    challenge = headers.get("www-authenticate")
    scheme, rest = challenge.split(" ", 1)
    pieces = rest.split(",")
    params = {}
    for piece in pieces:
        key, value = piece.split("=", 1)
        params[key.strip()] = value.strip().strip('"')

    if(scheme == "digest"):
