
import hashlib  # Library supplies hashing algorithms
import socket   # Library supplies endpoint sockets
import sys      # Library supplies functions for exiting the script

HOST = "localhost"  # Hostname of the server, as specified for local testing
PORT = 8080         # Port on which the server listens

# Ask the user for the credentials used to authenticate with the server
username = input("username: ").strip()
password = input("password: ").strip()

# Hash the password with SHA-256 to match the format stored in passwords.txt
hashed_password = hashlib.sha256(password.encode("utf-8")).hexdigest()


# Send an HTTP request through a TCP socket and return the server's response as text
def send_request(request):
    # Create a TCP socket using IPv4
    plain_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Connect to the server and send the HTTP request as UTF-8 bytes
        plain_socket.connect((HOST, PORT))
        plain_socket.sendall(request.encode("utf-8"))

        # Collect the response until the server closes the connection
        reply = b""
        while True:
            chunk = plain_socket.recv(4096) # Receive up to 4096 bytes

            # An empty byte sequence indicates that the connection has closed
            if not chunk:
                break

            # Append the received bytes to the accumulated response
            reply += chunk
    finally:
        # Always close the socket, including if an error occurs
        plain_socket.close()

    # Decode the response, replacing any invalid UTF-8 sequences
    return reply.decode("utf-8", errors="replace")


# Send an initial request without credentials to obtain an authentication challenge
first_request = (
    "GET / HTTP/1.1\r\n"       # Request the root resource using HTTP/1.1
    f"Host: {HOST}:{PORT}\r\n"  # Identify the target host and port
    "Connection: close\r\n"    # Ask the server to close the connection after responding
    "\r\n"                     # Mark the end of the HTTP request headers
)

# Send the initial request and store the server's response
text = send_request(first_request)

# Separate the HTTP headers from the response body at the first empty line
parts = text.split("\r\n\r\n", 1)

# Stop if the response does not contain a valid header section and body separator
if len(parts) < 2:
    print("Malformed reply:")
    print(text)
    sys.exit(1) # Exit system

# Store the response headers and body separately
head, body = parts

# Split the response header section into individual lines
lines = head.split("\r\n")

# Check that the response contains an HTTP status line
if not lines or not lines[0].startswith("HTTP/"):
    print("Malformed HTTP status line:")
    print(head)
    sys.exit(1)

# Extract the status line and the remaining header lines
status_line = lines[0]
header_lines = lines[1:]

# Split the status line into the HTTP version, status code and reason phrase
status_parts = status_line.split(" ", 2)

# Check that the status line contains a status code
if len(status_parts) < 2 or not status_parts[1].isdigit():
    print("Malformed HTTP status line:")
    print(status_line)
    sys.exit(1)

# Convert the status code from text to an integer
status_code = int(status_parts[1])

# Display the status code returned by the initial request
print(f"Initial response status: {status_code}")

# Create a dictionary for looking up response headers by name
headers = {}

# Parse each response header into its name and value
for line in header_lines:
    # Ignore lines that do not contain a header-name separator
    if ":" not in line:
        continue

    # Separate the header name from its value at the first colon
    name, value = line.split(":", 1)

    # Normalise the header name and remove surrounding whitespace
    headers[name.lower()] = value.strip()

# If the initial request succeeded without authentication, display its page content
if status_code == 200:
    print(body)

# If authentication is required, process the server's Digest challenge
elif status_code == 401:
    # Retrieve the authentication challenge from the response headers
    challenge = headers.get("www-authenticate")

    # Stop if the server did not provide an authentication challenge
    if not challenge:
        print("The server returned 401 without an authentication challenge.")
        sys.exit(1)

    # Separate the authentication scheme from its challenge parameters
    challenge_parts = challenge.split(" ", 1)

    # Check that the challenge contains both a scheme and parameters
    if len(challenge_parts) != 2:
        print("Malformed authentication challenge:")
        print(challenge)
        sys.exit(1)

    # Store the scheme and the comma-separated challenge parameters
    scheme, rest = challenge_parts

    # Continue only if the server requests Digest authentication
    if scheme.lower() != "digest":
        print(f"Unsupported authentication scheme: {scheme}")
        sys.exit(1)

    # Split the challenge into individual parameters
    pieces = rest.split(",")

    # Store the challenge parameters in a dictionary
    params = {}
    for piece in pieces:
        # Separate each parameter into its name and value
        key, separator, value = piece.partition("=")

        # Reject malformed parameters that do not contain an equals sign
        if not separator:
            print("Malformed authentication parameter:")
            print(piece)
            sys.exit(1)

        # Remove surrounding whitespace and quotation marks
        params[key.strip()] = value.strip().strip('"')

    # Retrieve the realm and nonce supplied by the server
    realm = params.get("realm")
    nonce = params.get("nonce")

    # Stop if the challenge does not provide the required values
    if not realm or not nonce:
        print("The authentication challenge is missing the realm or nonce.")
        sys.exit(1)

    # Set the resource path and HTTP method to match the request being authenticated
    uri = "/"
    method = "GET"

    # 1. Calculate HA1 using the username, realm and SHA-256-hashed password
    ha1_input = f"{username}:{realm}:{hashed_password}"
    ha1 = hashlib.md5(ha1_input.encode("utf-8")).hexdigest()

    # 2. Calculate HA2 using the HTTP method and requested URI
    ha2_input = f"{method}:{uri}"
    ha2 = hashlib.md5(ha2_input.encode("utf-8")).hexdigest()

    # 3. Calculate the final response digest using HA1, the nonce and HA2
    response_input = f"{ha1}:{nonce}:{ha2}"
    response_hash = hashlib.md5(response_input.encode("utf-8")).hexdigest()

    # 4. Construct the Authorization header with the required Digest fields
    auth_header_value = (
        f'Digest username="{username}", '  # Identify the user attempting to authenticate
        f'realm="{realm}", '                # Specify the authentication realm
        f'nonce="{nonce}", '                # Include the nonce from the server's challenge
        f'uri="{uri}", '                    # Specify the requested resource path
        f'response="{response_hash}"'       # Provide the calculated digest for verification
    )

    # 5. Build the second HTTP request with the Authorization header
    second_request = (
        f"GET {uri} HTTP/1.1\r\n"             # Request the specified resource
        f"Host: {HOST}:{PORT}\r\n"            # Identify the target host and port
        f"Authorization: {auth_header_value}\r\n"  # Include the Digest credentials
        "Connection: close\r\n"               # Ask the server to close the connection after responding
        "\r\n"                                # Mark the end of the HTTP request headers
    )

    # Send the authenticated request and collect the server's response
    final_text = send_request(second_request)

    # Separate the final response headers from the page content
    final_parts = final_text.split("\r\n\r\n", 1)

    # Check that the authenticated response has a header section and body separator
    if len(final_parts) < 2:
        print("Malformed authenticated response:")
        print(final_text)
        sys.exit(1)

    # Store the authenticated response headers and body
    final_head, final_body = final_parts

    # Extract the status line from the authenticated response headers
    final_lines = final_head.split("\r\n")
    final_status_line = final_lines[0] if final_lines else ""

    # Validate the final HTTP status line before extracting its status code
    final_status_parts = final_status_line.split(" ", 2)
    if (
        not final_status_line.startswith("HTTP/")
        or len(final_status_parts) < 2
        or not final_status_parts[1].isdigit()
    ):
        print("Malformed authenticated HTTP status line:")
        print(final_head)
        sys.exit(1)

    # Convert and display the status code returned by the authenticated request
    final_status_code = int(final_status_parts[1])
    print(f"Authenticated response status: {final_status_code}")

    # Display the complete response headers for inspection
    print(final_head)

    # Display the retrieved page content when authentication succeeds
    if final_status_code == 200:
        print(final_body)

# Handle any other status code returned by the initial request
else:
    print(f"Request failed with HTTP status {status_code}.")
    print(body)
