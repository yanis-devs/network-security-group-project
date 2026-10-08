import socket
import hashlib
import getpass

HOST = "127.0.0.1"
PORT = 8080
REALM = "auth"          # has to match REALM in digest_auth.py
NONCE = "simplenonce"   # has to match NONCE in digest_auth.py


def md5(text):
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def make_digest_response(username, password, method, uri):
    # The server's passwords.txt only ever stores SHA256(password), never the
    # real password. So on the server side, that SHA256 hash gets used as a
    # stand-in for the password when building the auth hash.
    # We have to copy that here: hash the password with SHA256 first, then
    # use THAT (not the plain password) to build our response, otherwise our
    # hash won't match what the server calculates.
    password_hash = sha256(password)

    ha1 = md5(f"{username}:{REALM}:{password_hash}")
    ha2 = md5(f"{method}:{uri}")
    return md5(f"{ha1}:{NONCE}:{ha2}")


def read_full_response(sock):
    # Keeps reading from the socket until we have the full response:
    # first the headers (up to the blank line), then the body (using
    # Content-Length if the server gave us one).
    data = b""

    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            return data
        data += chunk

    headers_part, _, body = data.partition(b"\r\n\r\n")

    content_length = None
    for line in headers_part.decode("iso-8859-1").split("\r\n")[1:]:
        name, _, value = line.partition(":")
        if name.strip().lower() == "content-length":
            content_length = int(value.strip())

    while True:
        if content_length is not None and len(body) >= content_length:
            break
        chunk = sock.recv(4096)
        if not chunk:
            break
        body += chunk

    return headers_part + b"\r\n\r\n" + body


def parse_response(raw):
    # Splits the raw HTTP response text into status code, headers and body
    headers_part, _, body = raw.partition(b"\r\n\r\n")
    lines = headers_part.decode("iso-8859-1").split("\r\n")

    # first line looks like: HTTP/1.1 200 OK
    parts = lines[0].split(" ", 2)
    status_code = int(parts[1])
    reason = parts[2] if len(parts) > 2 else ""

    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers[name.strip()] = value.strip()

    return status_code, reason, headers, body


def main():
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    path = input("Path to request [/]: ") or "/"

    digest_response = make_digest_response(username, password, "GET", path)

    # building the raw HTTP request by hand (no requests library here, just sockets)
    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        f'Authorization: Digest username="{username}", realm="{REALM}", '
        f'nonce="{NONCE}", uri="{path}", response="{digest_response}"\r\n'
        f"Connection: close\r\n"
        f"\r\n"
    )

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        sock.sendall(request.encode("utf-8"))
        raw_response = read_full_response(sock)

    status_code, reason, headers, body = parse_response(raw_response)

    print(f"\nStatus: {status_code} {reason}")
    print("Headers:")
    for name, value in headers.items():
        print(f"  {name}: {value}")
    print("\nBody:")
    print(body.decode("utf-8", "replace"))


if __name__ == "__main__":
    main()
