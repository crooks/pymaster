#!/usr/bin/python
#
# vim: tabstop=4 expandtab shiftwidth=4 noautoindent
#
# nymserv.py - A Basic Nymserver for delivering messages to a shared mailbox
# such as alt.anonymous.messages.
#
# Copyright (C) 2012 Steve Crook <steve@mixmin.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 3, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTIBILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
# for more details.
#
# You should have received a copy of the GNU General Public License along with
# this program.  If not, see <http://www.gnu.org/licenses/>.

import struct
import sys
import logging
from Crypto.Cipher import DES3, PKCS1_v1_5
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA
import Crypto.Random
from Config import config
import timing
import Chain
import email.message
import KeyManager
import Utils


log = logging.getLogger("Pymaster.EncodePacket")


class ValidationError(Exception):
    pass


class PacketInfo():
    def intermediate_hop(self, nexthop):
        """Packet type 0 (intermediate hop):
           19 Initialization vectors      [152 bytes]
           Remailer address               [ 80 bytes]
        """
        ivs = []
        for iv in range(18):
            ivs.append(Crypto.Random.get_random_bytes(8))
        self.addy = nexthop
        self.ivs = ivs

    def final_hop(self):
        """Packet type 1 (final hop):
           Message ID                     [ 16 bytes]
           Initialization vector          [  8 bytes]
        """
        self.messageid = Crypto.Random.get_random_bytes(16)
        self.iv = Crypto.Random.get_random_bytes(8)

    def final_partial(self, chunknum, numchunks):
        """Packet type 2 (final hop, partial message):
           Chunk number                   [  1 byte ]
           Number of chunks               [  1 byte ]
           Message ID                     [ 16 bytes]
           Initialization vector          [  8 bytes]
        """
        self.chunknum = chunknum
        self.numchunks = numchunks
        self.messageid = Crypto.Random.get_random_bytes(16)
        self.iv = Crypto.Random.get_random_bytes(8)


class EncryptedHeader():
    def make_header(self, odes3key, oiv, msg_type):
        """Packet ID                            [ 16 bytes]
           Triple-DES key                       [ 24 bytes]
           Packet type identifier               [  1 byte ]
           Packet information      [depends on packet type]
           Timestamp                            [  7 bytes]
           Message digest                       [ 16 bytes]
           Random padding               [fill to 328 bytes]
        """
        packetid = Crypto.Random.get_random_bytes(16)
        des3key = Crypto.Random.get_random_bytes(24)
        ts_sig = struct.pack('BBBBB', 48, 48, 48, 48, 0)
        timestamp = ts_sig + struct.pack('<H', timing.epoch_days())
        info = PacketInfo()
        if msg_type ==0:
            info.intermediate_hop(addy)
            packet = struct.pack("@16s24sB152s80s7s",
                                 packetid,
                                 des3key,
                                 msg_type,
                                 ''.join(info.ivs),
                                 info.addy,
                                 timestamp)
        if msg_type == 1:
            info.final_hop()
            packet = struct.pack("@16s24sB16s8s7s",
                                 packetid,
                                 des3key,
                                 msg_type,
                                 info.messageid,
                                 info.iv,
                                 timestamp)
        if msg_type == 2:
            info.final_partial()
            packet = struct.pack("@16s24sBBB16s8s7s",
                                 packetid,
                                 des3key,
                                 msg_type,
                                 info.chunknum,
                                 info.numchunks,
                                 info.messageid,
                                 info.iv,
                                 timestamp)
        digest = MD5.new(data=packet).digest()
        packet += digest
        pad = 328 - len(packet)
        packet += Crypto.Random.get_random_bytes(pad)
        desobj = DES3.new(odes3key, DES3.MODE_CBC, IV=oiv)
        self.packet = desobj.encrypt(packet)
        assert len(self.packet) == 328
        self.des3key = des3key
        self.info = info


class OuterHeader():
    """Public key ID                [  16 bytes]
       Length of RSA-encrypted data [   1 byte ]
       RSA-encrypted session key    [ 128 bytes]
       Initialization vector        [   8 bytes]
       Encrypted header part        [ 328 bytes]
       Padding                      [  31 bytes]
    """
    def make_outer(self, rem_data, msg_type):
        keyid = rem_data[1].decode('hex')
        # This 3DES key and IV are only used to encrypt the 328 Byte Inner
        # Header.  The 3DES key is then RSA Encrypted using the Remailer's
        # Public key.
        des3key = Crypto.Random.get_random_bytes(24)
        iv = Crypto.Random.get_random_bytes(8)
        pkcs1 = PKCS1_v1_5.new(rem_data[4])
        rsakey = pkcs1.encrypt(des3key)
        # Why does Mixmaster record the RSA data length when the spec
        # allows for nothing but 1024 bit keys?
        lenrsa = len(rsakey)
        assert lenrsa == 128
        inner = EncryptedHeader()
        inner.make_header(des3key, iv, msg_type)
        outer_header = struct.pack('16sB128s8s328s31s',
                                   keyid,
                                   lenrsa,
                                   rsakey,
                                   iv,
                                   inner.packet,
                                   Crypto.Random.get_random_bytes(31))
        assert len(outer_header) == 512
        self.outer_header = outer_header
        self.inner = inner


class Body():
    def encode(self, msgobj):
        plain = msgobj.get_payload()
        length = len(plain)
        payload = struct.pack('<L', length)
        payload += self.encode_header(msgobj['To'])
        payload += struct.pack('B', 0)
        #TODO Somehow the above process needs to be repeated for header lines.
        payload += plain
        payload += Crypto.Random.get_random_bytes(10240 - len(payload))
        assert len(payload) == 10240
        self.payload = payload

    def encode_header(self, header):
        """This function takes a standard comma-separated header, such as the
        To: header and converts it into the format required by Mixmaster,
        which is:
        Number of destination fields   [        1 byte]
        Destination fields             [ 80 bytes each]
        Number of header line fields   [        1 byte]
        Header lines fields            [ 80 bytes each]
        """
        fields = header.split(',')
        # The return string begins with the single-Byte count of the fields.
        headstr = struct.pack('B', len(fields))
        for field in fields:
            field = field.strip()
            padlen = 80 - len(field)
            headstr += field + ("\x00" * padlen)
        return headstr


def mixprep(binary):
    """Take a binary string, encode it as Base64 and wrap it to lines of
       length n.
    """
    # This is the wrap width for Mixmaster Base64
    n = 40
    length = len(binary)
    digest = MD5.new(data=binary).digest().encode("base64")
    s = binary.encode("base64")
    s = ''.join(s.split("\n"))
    header = "::\n"
    header += ("Remailer-Type: mixmaster-%s\n\n"
               % config.get('general', 'version'))
    header += "-----BEGIN REMAILER MESSAGE-----\n"
    header += "%s\n" % length
    # No \n after digest.  The Base64 encoding adds it.
    header += "%s" % digest
    payload = ""
    while len(s) > 0:
        payload += s[:n] + "\n"
        s = s[n:]
    payload += "-----END REMAILER MESSAGE-----\n"
    return header + payload


def randhop(packet):
    rem_data = exitnode()
    header = OuterHeader()
    header.make_outer(rem_data, 1)
    payload = (header.outer_header +
               Crypto.Random.get_random_bytes(9728))
    assert len(payload) == 10240
    desobj = DES3.new(header.inner.des3key,
                      DES3.MODE_CBC,
                      IV=header.inner.info.iv)
    payload += desobj.encrypt(packet.dbody)
    assert len(payload) == 20480
    msgobj = email.message.Message()
    msgobj.add_header('To', rem_data[0])
    msgobj.set_payload(mixprep(payload))
    return msgobj


def dummy():
    rem_data = randnode()
    outhead = OuterHeader()
    outhead.make_outer(rem_data, 1)
    header = (outhead.outer_header +
              Crypto.Random.get_random_bytes(9728))
    assert len(header) == 10240
    # Number of Destinations (1)
    payload = struct.pack("B", 1)
    # Idenitfy this as a Dummy message
    payload += "null:" + ("\x00" * 75)
    # Number of Headers (None in this instance)
    payload += struct.pack("B", 0)
    # pad fake payload to 10240 Bytes
    payload += Crypto.Random.get_random_bytes(10158)
    desobj = DES3.new(outhead.inner.des3key,
                      DES3.MODE_CBC,
                      IV=outhead.inner.info.iv)
    payload = desobj.encrypt(payload)
    assert len(payload) == 10240
    msgobj = email.message.Message()
    msgobj.add_header('To', rem_data[0])
    msgobj.set_payload(mixprep(header + payload))
    f = open(Utils.pool_filename('o'), 'w')
    f.write(msgobj.as_string())
    f.close()


def exitmsg():
    rem_data = exitnode('pymaster')
    header = OuterHeader()
    header.make_outer(rem_data, 1)
    headers = (header.outer_header +
               Crypto.Random.get_random_bytes(9728))
    assert len(headers) == 10240
    desobj = DES3.new(header.inner.des3key,
                      DES3.MODE_CBC,
                      IV=header.inner.info.iv)
    msg = email.message.Message()
    msg['To'] = 'steve@mixmin.net'
    msg.set_payload("Test Message")
    body = Body()
    body.encode(msg)
    payload = desobj.encrypt(body.payload)
    assert len(payload) == 10240
    return mixprep(headers + payload)


def exitnode(name=None):
    # pubring[0]    Email Address
    # pubring[1]    Key ID (Hex encoded)
    # pubring[2]    Version
    # pubring[3]    Capabilities
    # pubring[4]    Pycrypto Key Object
    if name is None:
        name = chain.randexit()
    rem_data = pubring[name]
    log.debug("Selected Exit-node: %s <%s>", name, rem_data[0])
    return rem_data


def randnode(name=None):
    # pubring[0]    Email Address
    # pubring[1]    Key ID (Hex encoded)
    # pubring[2]    Version
    # pubring[3]    Capabilities
    # pubring[4]    Pycrypto Key Object
    if name is None:
        name = chain.randany()
    rem_data = pubring[name]
    log.debug("Selected random node: %s <%s>", name, rem_data[0])
    return rem_data


def pubring_headers():
    if len(pubring.headers) == 0:
        pubring.read_pubring()
    return pubring.headers


pubring = KeyManager.Pubring()
chain = Chain.Chain()
if (__name__ == "__main__"):
    logfmt = config.get('logging', 'format')
    datefmt = config.get('logging', 'datefmt')
    log = logging.getLogger("Pymaster")
    log.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(fmt=logfmt, datefmt=datefmt))
    log.addHandler(handler)

    print exitmsg()
