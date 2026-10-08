from py_http_server.middlewares import CompressMiddleware, BasicAuthMiddleware, DefaultMiddleware
from py_http_server.routers import FileRouter
from py_http_server.networking import TCPAddress
from py_http_server import app_main

app_main(
    handler_chain=DefaultMiddleware(
        BasicAuthMiddleware(
            next=FileRouter("."),
            credentials={"test":"abcd1234"}
        )
    ),
   http_listeners=[
#    https_listeners=[
        TCPAddress("127.0.0.1", 8080),
        TCPAddress("::1", 8080),
    ],
 #  https_key_file="./key.pem",
  # https_cert_file="./cert.pem"
)
