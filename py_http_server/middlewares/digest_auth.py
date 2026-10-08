from ..common import RequestHandlerABC, RequestHandler, HeaderContainer, NO_CACHE_HEADERS
from ..http.request import HTTPRequest
from ..http.response import HTTPResponseFactory
from ..networking import ConnectionInfo
from .. import log
import hashlib

LOG = log.getLogger("middlewares.digest_auth")

# These two values have to match on both the server (here) and the client.
REALM = "auth"
NONCE = "simplenonce"  # normally this would be random and change often, but we're keeping it fixed/simple for this project


def md5(text):
    # just a shortcut so we don't have to write .encode().hexdigest() every time
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def read_passwords_file(pwdfile):
    # Loads passwords.txt into a dict like {"root": "5e8848...", "alice": "5ef2c3..."}
    # Each line in the file looks like: username:sha256hash
    users = {}

    with open(pwdfile, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line == "":
                continue  # skip empty lines

            username, _, password_hash = line.partition(":")

            if username == "" or password_hash == "":
                LOG.warning(f"Skipping bad line in password file: {line}")
                continue

            users[username] = password_hash.lower()

    return users


class DigestAuthMiddleware(RequestHandlerABC):
    # This checks the "Authorization: Digest ..." header on each request.
    #
    # How it works:
    # The client never sends the actual password, it sends a hash that proves
    # it KNOWS the password, without sending the password itself.
    # We calculate the same hash on our side using the password file, and if
    # they match, the user is authenticated.
    #
    # Important: passwords.txt stores SHA256(password), not the plain password.
    # So instead of using the real password when we build our hash, we just use
    # that stored SHA256 value directly as a stand-in for the password. The
    # client has to do the exact same thing (see client.py), otherwise the
    # hashes won't match.

    def __init__(self, next, pwdfile):
        self.next = next
        self.users = read_passwords_file(pwdfile)
        self.http = HTTPResponseFactory(NO_CACHE_HEADERS)

    def parse_auth_header(self, header_value):
        # turns: username="bob", realm="auth", response="abc123"
        # into:  {"username": "bob", "realm": "auth", "response": "abc123"}
        fields = {}
        for part in header_value.split(","):
            key, _, value = part.strip().partition("=")
            fields[key] = value.strip('"')
        return fields

    def check_credentials(self, header_value, request):
        # header_value looks like: Digest username="bob", realm="auth", uri="/", response="..."
        scheme, _, data = header_value.partition(" ")

        if scheme != "Digest" or data == "":
            return False

        fields = self.parse_auth_header(data)
        username = fields.get("username")
        uri = fields.get("uri")
        sent_response = fields.get("response")

        # if we don't know this user, or something's missing, reject straight away
        if username not in self.users or not uri or not sent_response:
            LOG.warning("Missing fields or unknown user in Authorization header.")
            return False

        password_hash = self.users[username]

        # This is the standard digest auth formula (HA1 -> HA2 -> final response),
        # just using password_hash instead of the real password.
        ha1 = md5(f"{username}:{REALM}:{password_hash}")
        ha2 = md5(f"{request.method}:{uri}")
        expected_response = md5(f"{ha1}:{NONCE}:{ha2}")

        if sent_response == expected_response:
            return True

        LOG.warning("Wrong username/password in Authorization header.")
        return False

    def __call__(self, conn_info: ConnectionInfo, request: HTTPRequest):
        auth_header = request.headers.get("Authorization")

        if auth_header and self.check_credentials(auth_header, request):
            # credentials are correct, let the request continue normally
            return self.next(conn_info, request)

        # no auth header, or wrong credentials -> ask the client to authenticate
        return self.http.status(
            401,
            HeaderContainer({"WWW-Authenticate": f'Digest realm="{REALM}", nonce="{NONCE}"'}),
        )
