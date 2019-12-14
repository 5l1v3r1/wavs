#/usr/bin/python3

# author:       Ryan Ritchie
# student no:   17019225
# email:        ryan2.ritchie@live.uwe.ac.uk
# file:         utils.py

# aesthetics imports
try:
    import colorama

except:
    print('Required modules not installed. use pip install -r requirements.txt')
    exit(1)

from colorama import Fore, Back
colorama.init(autoreset=True)

def _print_status(message, type):
    assert(type in ['success', 'warning', 'info'])

    if type == 'success':
        colour = Fore.GREEN
        status_code = '+'
    elif type == 'warning':
        colour = Fore.RED
        status_code = '-'
    elif type == 'info':
        colour = Fore.BLUE
        status_code = '*'

    print(colour + '[{}] {}'.format(status_code, message))

def success(message):
    _print_status(message, 'success')

def warning(message):
    _print_status(message, 'warning')

def info(message):
    _print_status(message, 'info')
