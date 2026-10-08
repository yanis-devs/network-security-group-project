from ..networking.connection_socket import ConnectionSocket
from ..common import HTTP_VERSIONS, HeaderContainer
import urllib.parse


class HTTPRequest:
    """
    Represents an incoming HTTP Request.
    
    This class encapsulates all components of an HTTP request (method, path,
    query parameters, headers, HTTP version, and payload body) and provides
    a method (`receive_from`) to parse raw binary data from a network socket.
    """
    def __init__(
        self,
        method: str,
        path: str,
        query: str,
        headers: HeaderContainer,
        version: str,
        body: bytes,
    ):
        self.method = method
        self.path = path
        self.query = query
        self.version = version
        self.headers = headers
        self.body = body

    @property
    def method(self):
        return self.__method

    @method.setter
    def method(self, value: str):
        self.__method = value

    @property
    def path(self):
        return self.__path

    @path.setter
    def path(self, value: str):
        self.__path = value

    @property
    def query(self):
        return self.__query

    @query.setter
    def query(self, value: str):
        self.__query = value

    @property
    def version(self):
        return self.__version

    @version.setter
    def version(self, value: str):
        self.__version = value.upper()

    @property
    def headers(self):
        return self.__headers

    @headers.setter
    def headers(self, value: HeaderContainer):
        self.__headers = value

    @property
    def body(self):
        return self.__body

    @body.setter
    def body(self, value: bytes):
        self.__body = value

    def to_url(self, host: str, schema: str):
        quoted_path = urllib.parse.quote(self.__path)
        return f"{schema}://{host}{quoted_path}{self.__query}"

    def __str__(self):
        quoted_path = urllib.parse.quote(self.__path)
        return f"{self.__method} {quoted_path}{self.__query} {self.__version}"

    @staticmethod
    def receive_from(
        conn: ConnectionSocket,
        max_content_length: int = 10_000_000,
        max_header_size: int = 32768,
        recv_buffer_size: int = 32768,
    ):
        """
        Reads raw bytes from a socket and parses them into an HTTPRequest object.
        Header blocks are separated from the body by CRLF CRLF (b"\r\n\r\n").
        """
        response = b""
        while b"\r\n\r\n" not in response:
            response += conn.recv(recv_buffer_size)
            if len(response) > max_header_size:
                raise ValueError("Header size exceeds maximum allowed length")
        headers_raw, _, body = response.partition(b"\r\n\r\n") # <-- see below
        """
        The line above splits the HTTP response byte string into two parts 
        separated by the (\r\n\r\n) delimiter, which marks the standard boundary 
        between HTTP headers and the body.
        - response: Contains the raw data received over a network socket.
        - .partition(b"\r\n\r\n") searches for the first occurrence of b"\r\n\r\n" and 
           splits the byte string into a 3-element tuple:
           :: Everything before the delimiter (assigned to headers_raw).
           :: The delimiter itself (b"\r\n\r\n", assigned to _ to signal it is discarded).
           :: Everything after the delimiter (assigned to body).
        """

        # parse the Http header fields
        try:
            # convert raw bytes to strings
            header_lines = headers_raw.decode(encoding="ascii").split("\r\n")

            # parse first header line, e.g., GET /index.html HTTP/1.1
            method, path, version = header_lines[0].split(" ")

            if version not in HTTP_VERSIONS:
                raise ValueError("Invalid HTTP version")

            # Extract and store key-value header pairs, e.g., Host, User-Agent, etc.
            headers = HeaderContainer()
            for line in header_lines[1:]:
                key, _, val = line.partition(":")
                headers[key] = val.strip()
        except (IndexError, ValueError, UnicodeDecodeError) as exc:
            raise ValueError(f"Request header is malformed. Exception: {exc}")

        # Extract Content-Length to determine if an HTTP payload body exists
        content_length = (
            int(headers["Content-Length"])
            if headers.get("Content-Length", "").isdigit()
            else None
        )

        # read remaining body bytes from the socket stream, if required
        if content_length:
            if content_length > max_content_length:
                raise ValueError("Content-Length is too large")
            while len(body) < content_length:
                body += conn.recv(min(recv_buffer_size, content_length - len(body)))

        # Parse percent encoding
        # Warning: This step is necessary to prevent unexpected vulnerabilities
        path = urllib.parse.unquote(path)

        # Split the path to actual path and query, keeps the question mark
        path, qm, query = path.partition("?")
        query = qm + query

        # return an HttpRequest object with the relevant content
        return HTTPRequest(method, path, query, headers, version, body)
