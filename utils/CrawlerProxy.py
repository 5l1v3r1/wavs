import requests
from http.server import BaseHTTPRequestHandler

class CrawlerProxy(BaseHTTPRequestHandler):

    # GET
    def do_GET(self, body=True):
        hostname = '127.0.0.1:80'
        url = f'http://{hostname}{self.path}'
        req_header = self.parse_headers(self.headers.as_string())

        resp = requests.get(url, headers=req_header, verify=False, stream=True)

        if resp.status_code in [200, 302]:
            print(f'[+] Found: {self.path}')

        # Send response status code
        self.send_response(resp.status_code)

        for key in resp.headers:
            self.send_header(key, resp.headers[key])

        # Send headers
        self.end_headers()

        self.wfile.write(resp.raw.data)
        return

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)

        hostname = '127.0.0.1:80'
        url = f'http://{hostname}{self.path}'
        req_header = self.parse_headers(self.headers.as_string())

        resp = requests.post(url, headers=req_header, data=body, verify=False, stream=True)

        if resp.status_code in [200, 302]:
            print(f'[+] Found (POST): {self.path}')

        # Send response status code
        self.send_response(resp.status_code)

        for key in resp.headers:
            self.send_header(key, resp.headers[key])

        # Send headers
        self.end_headers()

        self.wfile.write(resp.raw.data)
        return


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
