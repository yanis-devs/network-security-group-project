from ..common import RequestHandlerABC, RequestHandler, HeaderContainer, NO_CACHE_HEADERS
from ..http.request import HTTPRequest
from ..http.response import HTTPResponseFactory
from ..networking import ConnectionInfo
from .. import log
import base64

LOG = log.getLogger("middlewares.basic_auth")


class BasicAuthMiddleware(RequestHandlerABC):
    """
    Middleware that implements HTTP Basic Authentication.
    Requests are checked for a valid Authorization header.
    If authentication succeeds, the request is forwarded to the next handler.
    Otherwise, a 401 Unauthorized response is returned.
    """
    def __init__(self, next: RequestHandler, credentials: dict[str, str]):
        self.next = next
        self.__cred = credentials
        self.http = HTTPResponseFactory(NO_CACHE_HEADERS)
        """
        Initializes authentication middleware with downstream handler and user directory.

        :param next: The next RequestHandler in the middleware execution chain.
        :param credentials: Dictionary mapping plaintext usernames to plaintext passwords.
        """

    def __verify_authorization(self, header_value: str):
        """
        Parses and validates the contents of an HTTP 'Authorization' header.
        """

        # Split header scheme and payload (e.g. "Basic dXNlcjpwYXNz")
        auth_type, _, data = header_value.partition(" ")

        # Enforce that authentication scheme must explicitly be "Basic"
        if not data or auth_type != "Basic":
            return False

        # Base64 decode payload string and split username:password credential pair
        # Format after decoding: "username:password"
        username, _, password = (
            base64.b64decode(data).decode("utf-8", "replace").partition(":")
        )

        # Check credential match against configured user directory
        if username in self.__cred and self.__cred[username] == password:
            LOG.debug(f"Basic authentication correct credentials.")
            return True

        LOG.warning(f"Basic authentication incorrect credentials.")
        return False

    def __call__(self, conn_info: ConnectionInfo, request: HTTPRequest):
        """
        Callable interface executing request interception and access evaluation.

        If valid credentials are provided: Hands execution over to `self.next(...)`.
        If missing or invalid: Returns HTTP 401 Unauthorized with a `WWW-Authenticate` header.

        NOTE: __call__ is an example of a 'dunder' in Python, a double-underscore
        method. It allows an object instance to be called as if it was a function.
        
        In this case, it helps promote flexibility through inheritance. 
        BasicAuthMiddleware is defined as a child class of RequestHandlerABC
        which defines a generic 'call' method for handling the next stage
        of processing of an HttpRequest. BasicAuthMiddleware overrides this
        to handle it its own way. Elsewhere in the code, we can do the 
        following:

        handler = BasicAuthMiddleware()
        response = handler(conn_info, request)

        Here, the object 'handler' is being called as if it were a function
        """
        if "Authorization" in request.headers and self.__verify_authorization(
            request.headers["Authorization"]
        ):
            return self.next(conn_info, request)

        return self.http.status(
            401,
            HeaderContainer({"WWW-Authenticate": 'Basic realm="auth", charset="UTF-8"'}),
        )
