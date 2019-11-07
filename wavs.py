#/usr/bin/python3

# author:       Ryan Ritchie
# student no:   17019225
# email:        ryan2.ritchie@live.uwe.ac.uk
# file:         wavs.py

# core imports
import sys
import requests
import argparse
import unittest

# aesthetics imports
try:
    import colorama
except:
    print('colorama not installed. use pip install -r requirements.txt')

# argument parsing
arg_parser = argparse.ArgumentParser()
arg_parser.add_argument('host', help='The url of the web application to be scanned')
arg_parser.add_argument('--port', type=int, help='The port the web application is running on')
arg_parser.add_argument('--test')
args = arg_parser.parse_args()

class WebScanner():
    def __init__(self, host, port=80):
        # TODO: handle http/https
        self.host = host
        self.port = port

    def scan(self, wordlist_path):
        print('[*] Starting scan on {}:{}', self.host, self.port)

        #TODO: need to try random long string to see if we get 200
        # that means the application is returning 200 for everything
        # need to fuzz

        for word in open(wordlist_path, 'r').readlines():
            word = word.rstrip()
            if word[0] == '#':
                continue
            resp = requests.get('http://{}:{}/{}'.format(self.host, self.port, word))

            # TODO: handle different success response code
            if (resp.status_code in [200, 302]):
                print('/{}'.format(word))

class Test(unittest.TestCase):
    pass

if __name__ == '__main__':
    wscan = WebScanner(args.host, args.port)
    wscan.scan('/opt/SecLists/Discovery/Web-Content/raft-small-directories.txt')
