#!/usr/bin/env python3

import sys

if len(sys.argv) != 3:
    print(f'[-] usage: ./{sys.argv[0]} WORDLIST_FILE_PATH WORDLIST_TYPE')
    exit()

wl_path = sys.argv[1]
typer = sys.argv[2]

with open('counter.txt', 'r') as f:
    counter = f.read()
    counter = counter.replace('\n', '')
    counter = int(counter)

data = []
print(f'[+] Reading in file {wl_path}')
with open(wl_path, 'r') as f:
    for line in f.read().splitlines():
        line = f'{counter}£{line}£{typer}£0\n'
        data.append(line)
        counter += 1

with open('counter.txt', 'w') as f:
    f.write(str(counter + 1))

new_filename = 'final_import.txt'
print(f'[+] Writing file {new_filename}')
with open(new_filename, 'a') as f:
    for d in data:
        f.write(d)
