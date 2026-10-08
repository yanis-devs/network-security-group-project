from ..networking.connection_socket import ConnectionSocket
from ..common import STATUS_CODES, HeaderContainer
from .response_body import ResponseBody
from typing import Any, Optional
import json


class HTTPResponse:
    """
    Represents an outgoing HTTP Response.

    This class builds the raw HTTP status line, sets response headers, and manages
    the transmission of the response headers and optional payload body back to 
    the connected socket client.
    """
    def __init__(
        self,
        status_code: int,
        headers: HeaderContainer = HeaderContainer(),
        body: Optional[ResponseBody] = None,
    ):
        self.status_code = status_code
        self.headers = headers
        self.body = body

    @property
    def status_code(self):
        return self.__status_code

    @status_code.setter
    def status_code(self, value: int):
        self.__status_code = value

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
    def body(self, value: Optional[ResponseBody]):
        self.__body = value

    def send_to(self, conn: ConnectionSocket, http_version: str):
        """
        Formats and transmits the complete HTTP response over the provided network socket.
        """
        # Step 1: Compute and merge body-related headers (e.g., Content-Length, Transfer-Encoding)
        if self.body:
            self.__headers = self.body.process_headers(self.__headers)
        else:
            # state zero content length when no payload exists
            self.__headers["Content-Length"] = "0"

        # Format header key-value pairs into CRLF-delimited lines
        header_lines = "".join(
            f"{header}: {value}\r\n" for header, value in self.__headers.items()
        )

        # Construct status line (e.g., "HTTP/1.1 200 OK")
        status_code_str = str(self.__status_code)
        if self.__status_code in STATUS_CODES:
            status_code_str += f" {STATUS_CODES[self.__status_code]}"

        # Encode and send the complete response header block over the wire
        # HTTP protocol headers must use ASCII encoding.
        response_header = (
            f"{http_version} {status_code_str}\r\n{header_lines}\r\n".encode("ascii")
        )
        conn.send(response_header)

        # Transmit the message payload body if one is present
        if self.body:
            self.body.send_to(conn)

        # Flush socket buffers to ensure immediate transmission to the client
        conn.flush()


class HTTPResponseFactory:
    """
    Factory class providing helper methods to instantiate standardized HTTP responses.
    
    Simplifies producing common response types (JSON, HTML, plain text status messages, 
    and redirects) while handling default header merging and encoding automatically.
    """
    def __init__(
        self,
        default_headers: HeaderContainer = HeaderContainer(),
        default_encoding: str = "utf-8",
    ):
        self.default_headers = default_headers
        self.default_encoding = default_encoding

    def json(
        self,
        value: Any,
        status_code: int = 200,
        additional_headers: HeaderContainer = HeaderContainer(),
        encoding: Optional[str] = None,
    ) -> HTTPResponse:
        encoding = encoding if encoding else self.default_encoding
        headers = (
            self.default_headers
            | additional_headers
            | {"Content-Type": f"application/json; charset={encoding}"}
        )

        return HTTPResponse(
            status_code,
            headers,
            ResponseBody.from_bytes(json.dumps(value).encode(encoding)),
        )

    def html(
        self,
        value: str,
        status_code: int = 200,
        additional_headers: HeaderContainer = HeaderContainer(),
        encoding: Optional[str] = None,
    ) -> HTTPResponse:
        encoding = encoding if encoding else self.default_encoding
        headers = (
            self.default_headers
            | additional_headers
            | {"Content-Type": f"text/html; charset={encoding}"}
        )

        return HTTPResponse(
            status_code,
            headers,
            ResponseBody.from_bytes(value.encode(encoding)),
        )

    def status(
        self,
        status_code: int,
        additional_headers: HeaderContainer = HeaderContainer(),
        encoding: Optional[str] = None,
    ) -> HTTPResponse:
        encoding = encoding if encoding else self.default_encoding
        headers = self.default_headers | additional_headers

        if (
            status_code in STATUS_CODES
            and status_code >= 200
            and status_code not in [204, 205, 304]
        ):
            # Set the body to the status code text
            return HTTPResponse(
                status_code,
                headers | {"Content-Type": f"text/plain; charset={encoding}"},
                ResponseBody.from_bytes(STATUS_CODES[status_code].encode(encoding)),
            )

        # Status code is not allowed to have a body or is unknown
        return HTTPResponse(status_code, headers)

    def redirect(
        self,
        location: str,
        permanent: bool = False,
        additional_headers: HeaderContainer = HeaderContainer(),
    ) -> HTTPResponse:
        headers = additional_headers | {"Location": location}
        return self.status(301 if permanent else 302, headers)
