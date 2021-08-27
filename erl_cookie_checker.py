#!/usr/bin/env python3
import argparse
from os.path import isfile
from ERLPopper import *

def parse_str_or_file(in_str):
    '''
    Expecting:
        <string>
        - OR -
        <string_file>
    Where:
        <string> is a single item
        <string_file> is a newline-delimited list of <string>s
    '''

    list_lines = []
    if not isfile(in_str):
        list_lines = [in_str]
    else:
        list_lines = [x.strip() for x in open(in_str, 'r').readlines()]

    return list_lines

def main():
    # Parse args
    #  [TODO] implement custom argparse formatter for epilog
    parser = argparse.ArgumentParser(
            description='A script to test the security of Erlang nodes.',
            epilog='Example usage:  %(prog)s 127.0.0.1:12345 MYSECRETCOOKIE')

    parser.add_argument('target', action='store', type=parse_str_or_file, help='Target node <address>:<port>, or file containing newline-delimited list of <address>:<port> strings.')
    parser.add_argument('cookie', action='store', type=parse_str_or_file, help='Cluster cookie, or file containing newline-delimited list of <cookie> strings.')
    version_group = parser.add_mutually_exclusive_group()
    version_group.add_argument('--old', action='store_true', help='Use old handshake method (default).')
    version_group.add_argument('--new', action='store_true', help='Use new handshake method.')
    parser.add_argument('--verbose', action='store_true', help='Extra output for debugging.')
    parser.add_argument('--challenge', type=int, default=0, help='Set client challenge value.')

    args = parser.parse_args()

    version = 5
    if args.new:
        version = 6

    for target in args.target:
        for cookie in args.cookie:
            epop = ERLPopper(target=target, cookie=cookie, version=version, verbose=args.verbose, challenge=args.challenge, cmd=None)

            try:
                res = epop.check_cookie()
            except ERLPopper.StatusError as e:
                print(f"[E] Error status: '{repr(e.status)}', msg: '{e.message}'")
            except ERLPopper.EmptyResponseError as e:
                print(f"[E] Error response: '{e.message}'")
            except BrokenPipeError as e:
                print(f"[E] Broken pipe - is {target} up?")
            else:
                if res:
                    print(f"[+] Good cookie! Host: {target} Cookie: {cookie}")
                    break
                else:
                    if args.verbose: print("[-] Bad cookie!")

if __name__ == "__main__":
    main()
