import requests
import signal
from util_functions import info, success, warning
from http.server import HTTPServer, BaseHTTPRequestHandler

class HTTPProxy(BaseHTTPRequestHandler):

    # GET
    def do_GET(self, body=True):
        hostname = '127.0.0.1:80'
        url = f'http://{hostname}{self.path}'
        req_header = self.parse_headers(self.headers.as_string())

        resp = requests.get(url, headers=req_header, verify=False, stream=True)
        self.proxy_response_handle(resp)
        return


    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)

        hostname = '127.0.0.1:80'
        url = f'http://{hostname}{self.path}'
        req_header = self.parse_headers(self.headers.as_string())

        resp = requests.post(url, headers=req_header, data=body, verify=False, stream=True)
        self.proxy_response_handle(resp)
        return


    def proxy_response_handle(self, resp):
        if resp.status_code in [200, 302]:
            print(f'[+] Found: {self.path}')

        # Send response status code
        self.send_response(resp.status_code)

        for key in resp.headers:
            self.send_header(key, resp.headers[key])

        # Send headers
        self.end_headers()

        self.wfile.write(resp.raw.data)


    def parse_headers(self, headers_string):
        header_dict = {}

        # split the headers into lines
        header_list = headers_string.split('\n')

        for header in header_list:
            if not ':' in header:
                continue

            k,v = header.split(': ')
            header_dict[k] = v

        return header_dict


    def log_message(self, format, *args):
        """ supresses output
        """
        return


class InterceptingProxy:
    def __init__(self, host, port):
        self.running = False
        self.proxy = HTTPServer((host, port), HTTPProxy)

    def start(self):
        self.running = True
        self.run()

    def stop(self):
        self.running = False
        self.proxy.shutdown()

    def run(self):
        signal.signal(signal.SIGINT, self.stop)

        while self.running:
            self.proxy.handle_request()
