"""A tiny HTTPS server that mimics LLM API responses, for end-to-end tests.

usage: fake_llm.py CERT KEY PORT
"""

import json
import ssl
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length", 0)))
        if self.path.startswith("/v1/messages") and "stream=true" in self.path:
            self.stream_messages()
        elif self.path.startswith("/v1/messages"):
            self.json({"id": "msg_1", "usage": {"input_tokens": 25, "output_tokens": 154}})
        elif self.path.startswith("/v1/chat/completions"):
            self.json({"id": "chatcmpl-1", "usage": {"prompt_tokens": 12, "completion_tokens": 7}})
        else:
            self.send_error(404)

    def json(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def stream_messages(self):
        # Chunked, like real APIs. Closing the connection without a TLS close_notify instead
        # makes older curl/OpenSSL 3.0 (Ubuntu 22.04) fail with "unexpected eof".
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("transfer-encoding", "chunked")
        self.end_headers()
        events = [
            ("message_start", {"usage": {"input_tokens": 10, "output_tokens": 1}}),
            ("content_block_delta", {"delta": {"text": "Hello"}}),
            ("content_block_delta", {"delta": {"text": " world"}}),
            ("message_delta", {"usage": {"output_tokens": 42}}),
        ]
        for name, data in events:
            chunk = f"event: {name}\ndata: {json.dumps(data)}\n\n".encode()
            self.wfile.write(b"%x\r\n%s\r\n" % (len(chunk), chunk))
            self.wfile.flush()
            time.sleep(0.1)
        self.wfile.write(b"0\r\n\r\n")

    def log_message(self, *args):
        pass


def main():
    cert, key, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
