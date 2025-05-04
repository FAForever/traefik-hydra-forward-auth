from http.server import BaseHTTPRequestHandler, HTTPServer
import json

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/oauth2/introspect":
            self.serve_json()
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == "/oauth2/introspect":
            self.serve_json()
        else:
            self.send_error(404)

    def serve_json(self):
        with open("/app/introspect.json") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data.encode("utf-8"))

    def log_message(self, format, *args):
        return  # silence logs

if __name__ == "__main__":
    HTTPServer(("", 80), Handler).serve_forever()
