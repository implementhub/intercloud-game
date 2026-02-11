#!/usr/bin/env python3

import argparse
import ssl
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
import threading
import json
import os


BUNDLE_PATH = "/tmp/primary.bundle"   # oder /tmp/secondary.bundle

class BundleHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path not in ["/", "/bundle"]:
            self.send_response(404)
            self.end_headers()
            return

        if not os.path.exists(BUNDLE_PATH):
            self.send_response(500)
            self.end_headers()
            self.wfile.write(b"Bundle not found")
            return

        with open(BUNDLE_PATH, "r") as f:
            bundle = f.read()

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(bundle)))
        self.end_headers()

        self.wfile.write(bundle.encode())

        print(f"✓ Bundle served to {self.client_address[0]}")

    def log_message(self, format, *args):
        pass


def start_public_https_server(port):
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(
        "/home/azureuser/acme-lab/04-finalize/http-certificate.pem",
        "/home/azureuser/acme-lab/04-finalize/domain-key.pem"
    )

    server = ThreadingHTTPServer(("0.0.0.0", port), BundleHandler)
    server.socket = context.wrap_socket(server.socket, server_side=True)

    print(f"[PUBLIC] HTTPS score endpoint listening on :{port}")
    server.serve_forever()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--port', type=int, required=True)
    args = parser.parse_args()

    print("Start Bundle Download Server")
    threading.Thread(
        target=start_public_https_server,
        args=(args.port,),
        daemon=True
    ).start()

if __name__ == '__main__':
    main()