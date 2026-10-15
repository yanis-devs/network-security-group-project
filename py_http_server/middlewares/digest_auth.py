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

if status_code == 200:
    print(body)

headers = {}

for line in lines[1:]:
    name, value = line.split(":", 1)
    headers[name.lower()] = value.strip()

print(headers.get("www-authenticate"))

if status_code == 401:
    challenge = headers.get("www-authenticate")
    scheme, rest = challenge.split(" ", 1)
    pieces = rest.split(",")
    params = {}
    for piece in pieces:
        key, value = piece.split("=", 1)
        params[key.strip()] = value.strip().strip('"')

    if scheme == "digest":
        realm = params.get("realm")
        nonce = params.get("nonce")
        uri = "/"
        method = "GET"

        # 1. Calculate HA1 using the client's hashed_password
        ha1_input = f"{username}:{realm}:{hashed_password}"
        ha1 = hashlib.md5(ha1_input.encode("utf-8")).hexdigest()

        # 2. Calculate HA2
        ha2_input = f"{method}:{uri}"
        ha2 = hashlib.md5(ha2_input.encode("utf-8")).hexdigest()

        # 3. Calculate the final response digest
        response_input = f"{ha1}:{nonce}:{ha2}"
        response_hash = hashlib.md5(response_input.encode("utf-8")).hexdigest()

        # 4. Construct the Authorization header string matching server expectations
        auth_header_value = (
            f'Digest username="{username}", '
            f'realm="{realm}", '
            f'nonce="{nonce}", '
            f'uri="{uri}", '
            f'response="{response_hash}"'
        )

        # 5. Build and send the second (authenticated) request
        second_request = (
            f"GET {uri} HTTP/1.1\r\n"
            f"Host: {HOST}:{PORT}\r\n"
            f"Authorization: {auth_header_value}\r\n"
            "Connection: close\r\n"
            "\r\n"
        )

        print("\n--- Sending Authenticated Request ---")
        final_text = send_request(second_request)
        print(final_text)
