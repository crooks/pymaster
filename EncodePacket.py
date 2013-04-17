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


class EncodeError(Exception):
    pass


class PacketInfo():
    """Packet Info is a component of the Encrypted Header part of a Mixmaster
       message.  It is the only component with differing members for
       Intermediate, Exit and Partial Exit messages.
    """
    def intermediate_hop(self, nextaddy):
        """Packet type 0 (intermediate hop):
           19 Initialization vectors      [152 bytes]
           Remailer address               [ 80 bytes]
        """
        # 152 Random bytes equates to 19 IVs of 8 Bytes each.
        ivstr = Crypto.Random.get_random_bytes(152)
        fmt = "8s" * 19
        ivs = struct.unpack(fmt, ivstr)
        # The address of the next hop needs to be padded to 80 Chars
        padaddy = nextaddy + ('\x00' * (80 - len(nextaddy)))
        self.nextaddy = nextaddy
        self.ivs = ivs
        return struct.pack('@152s80s', ivstr, padaddy)

    def final_hop(self):
        """Packet type 1 (final hop):
           Message ID                     [ 16 bytes]
           Initialization vector          [  8 bytes]
        """
        messageid = Crypto.Random.get_random_bytes(16)
        iv = Crypto.Random.get_random_bytes(8)
        self.messageid = messageid
        self.iv = iv
        return struct.pack('@16s8s', messageid, iv)

    def final_partial(self, chunknum, numchunks, mid):
        """Packet type 2 (final hop, partial message):
           Chunk number                   [  1 byte ]
           Number of chunks               [  1 byte ]
           Message ID                     [ 16 bytes]
           Initialization vector          [  8 bytes]
        """
        self.chunknum = chunknum
        self.numchunks = numchunks
        self.messageid = mid
        self.iv = Crypto.Random.get_random_bytes(8)
        return struct.pack('@BB16s8s', chunknum, numchunks, mid, iv)


class InnerHeader():
    def __init__(self, rem_data, msgtype):
        self.pktinfo = PacketInfo()
        self.rem_data = rem_data
        self.msgtype = msgtype

    def make_header(self):
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
        timestamp = "0000\x00" + struct.pack('<H', timing.epoch_days())
        if self.msgtype == 0:
            pktinfo = self.pktinfo.intermediate_hop(self.rem_data['email'])
        elif self.msgtype == 1:
            pktinfo = self.pktinfo.final_hop()
        elif self.msgtype == 2:
            pktinfo = self.pktinfo.final_partial()
        pktlen = len(pktinfo)
        fmt = "@16s24sB%ss7s" % len(pktinfo)
        header = struct.pack(fmt,
                             packetid,
                             des3key,
                             self.msgtype,
                             pktinfo,
                             timestamp)
        digest = MD5.new(data=header).digest()
        header += digest
        if self.msgtype == 0:
            assert len(header) == 64 + 232
        elif self.msgtype == 1:
            assert len(header) == 64 + 24
        elif self.msgtype == 2:
            assert len(header) == 64 + 26
        else:
            raise EncodeError("Unknown message type")
        pad = 328 - len(header)
        self.des3key = des3key
        return header + Crypto.Random.get_random_bytes(pad)


class OuterHeader():
    """Public key ID                [  16 bytes]
       Length of RSA-encrypted data [   1 byte ]
       RSA-encrypted session key    [ 128 bytes]
       Initialization vector        [   8 bytes]
       Encrypted header part        [ 328 bytes]
       Padding                      [  31 bytes]
    """
    def __init__(self, rem_data, msgtype):
        self.rem_data = rem_data
        self.inner = InnerHeader(rem_data, msgtype)

    def make_header(self):
        keyid = self.rem_data['keyid'].decode('hex')
        # This 3DES key and IV are only used to encrypt the 328 Byte Inner
        # Header.  The 3DES key is then RSA Encrypted using the Remailer's
        # Public key.
        des3key = Crypto.Random.get_random_bytes(24)
        iv = Crypto.Random.get_random_bytes(8)
        desobj = DES3.new(des3key, DES3.MODE_CBC, IV=iv)
        pkcs1 = PKCS1_v1_5.new(self.rem_data['keyobj'])
        rsakey = pkcs1.encrypt(des3key)
        # Why does Mixmaster record the RSA data length when the spec
        # allows for nothing but 1024 bit keys?
        lenrsa = len(rsakey)
        assert lenrsa == 128
        header = struct.pack('16sB128s8s328s31s',
                            keyid,
                            lenrsa,
                            rsakey,
                            iv,
                            desobj.encrypt(self.inner.make_header()),
                            Crypto.Random.get_random_bytes(31))
        assert len(header) == 512
        return header


class Payload():
    """This class takes a Python email.message object and translates it into
       a Mixmaster payload.  The resulting payload is stored as self.dbody
       (decrytped body) as this matches the format used during Decode
       processing.  This means randhops can be processed without having to
       pass huge lumps of scalars for re-encoding to a random exit.
    """
    def __init__(self, msgobj):
        self.msgobj = msgobj

    def email2payload(self):
        if 'Dests' in self.msgobj:
            dests = self.msgobj['Dests'].split(",")
        else:
            raise EncodeError("No destinations specified")
        payload = self.encode_header(dests)
        heads = []
        for k in self.msgobj.keys():
            if not k == 'Dests':
                heads.append("%s: %s" % (k, self.msgobj[k]))
        payload += self.encode_header(heads)
        payload += self.msgobj.get_payload()
        length = struct.pack('<I', len(payload))
        payload = length + payload
        payload += Crypto.Random.get_random_bytes(10240 - len(payload))
        # dbody is the scalar expected withih the object passed to makemsg
        self.dbody = payload

    def encode_header(self, items):
        """This function takes a list of destinations or headers and converts
           them into the format required by Mixmaster, which is:
                Number of destination fields   [        1 byte]
                Destination fields             [ 80 bytes each]
                Number of header line fields   [        1 byte]
                Header lines fields            [ 80 bytes each]
        """
        # The return string begins with the single-Byte count of the fields.
        headstr = struct.pack('B', len(items))
        for item in items:
            item = item.strip()
            padlen = 80 - len(item)
            headstr += item + ("\x00" * padlen)
        return headstr


class Mixmaster(object):
    def __init__(self, pubring):
        self.pubring = pubring
        self.chain = Chain.Chain(pubring)
        # Easiest way to inject Dummies is to chain them through the local
        # remailer.  That way they can be stored in the pool like any other
        # received message.
        self.dummychain = "%s,*" % config.get('general', 'shortname')

    def dummy(self):
        msg = email.message.Message()
        # payload size is arbitrary as the payload class pads it with random
        # data to a length of 10240.
        msg.set_payload(Crypto.Random.get_random_bytes(10))
        msg['Dests'] = 'null:'
        # The payload object created here will be extended by the various
        # fuctions that tweak the message into the final format for pool
        # injection.
        packet = Payload(msg)
        # email2payload compiles the Mixmaster payload; the second 10240 Bytes
        # of the overall Mixmaster packet.  This is stored in packet.dbody.
        packet.email2payload()
        # The chain comprises two hops; the first is the local remailer, the
        # second a randomly selected node.
        chain = self.chain.chain(self.dummychain)
        self.final_hop(packet, chain.pop())
        self.intermediate_hops(packet, chain)
        f = open(Utils.pool_filename('m'), 'wb')
        f.write(packet.payload)
        f.close()

    def randhop(self, packet):
        """Randhop is passed the decrypted message packet object that includes
           a dbody (decrypted body) scalar.  This is the only part needed for
           randhopping.
        """
        exitnode = self.chain.randexit()
        return self.makemsg(packet, chainstr=exitnode)

    def makemsg(self, packet, chainstr=None):
        if chainstr is None:
            chain = self.chain.chain()
        else:
            chain = self.chain.chain(chainstr)
        self.final_hop(packet, chain.pop())
        self.intermediate_hops(packet, chain)
        return self.packet2mail(packet)

    def final_hop(self, packet, node):
        # packet must be an object with a dbody scalar.
        assert hasattr(packet, "dbody")
        # First create the payload and the header for it.
        rem_data = self.nodedata(name=node)
        outer = OuterHeader(rem_data, 1)
        # This is always the first header so it creates the list of headers.
        headers = [outer.make_header()]
        desobj = DES3.new(outer.inner.des3key,
                          DES3.MODE_CBC,
                          IV=outer.inner.pktinfo.iv)
        packet.dbody = desobj.encrypt(packet.dbody)
        # The remailer that will pass messages to this remailer needs to
        # know the email address of the node to pass it to.
        packet.nextaddy = rem_data['email']
        packet.headers = headers

    def intermediate_hops(self, packet, chain):
        # packet must be an object with a dbody scalar.
        assert hasattr(packet, "dbody")
        assert hasattr(packet, "headers")
        assert hasattr(packet, "nextaddy")
        # When compiling intermediate headers, there must already be one, and
        # only one header; the exit header.
        assert len(packet.headers) == 1
        while len(chain) > 0:
            numheads = len(packet.headers)
            thishop = chain.pop()
            rem_data = self.nodedata(name=thishop)
            # This uses the rem_data dict to pass the next hop address
            # to the pktinfo section of Intermediate messages.
            rem_data['nextaddy'] = packet.nextaddy
            outer = OuterHeader(rem_data, 0)
            header = outer.make_header()
            for h in range(numheads):
                desobj = DES3.new(outer.inner.des3key,
                                  DES3.MODE_CBC,
                                  IV=outer.inner.pktinfo.ivs[h])
                packet.headers[h] = desobj.encrypt(packet.headers[h])
            # All the headers are sorted, now we need to encrypt the payload
            # with the same IV as the final header.
            desobj = DES3.new(outer.inner.des3key,
                              DES3.MODE_CBC,
                              IV=outer.inner.pktinfo.ivs[18])
            packet.dbody = desobj.encrypt(packet.dbody)
            assert len(packet.dbody) == 10240
            packet.headers.insert(0, header)
            packet.nextaddy = rem_data['email']
        pad = Crypto.Random.get_random_bytes((20 - len(packet.headers)) * 512)
        packet.payload = ''.join(packet.headers) + pad + packet.dbody
        assert len(packet.payload) == 20480

    def packet2mail(self, packet):
        msgobj = email.message.Message()
        # We always want to send the message to the outer-most remailer.
        # Outer-most implies, the last remailer we encoded to.
        msgobj.add_header('To', packet.nextaddy)
        msgobj.set_payload(mixprep(packet.payload))
        return msgobj

    def nodedata(self, name=None, exit=False):
        """Select a remailer by shortname (or email) and return the dictionary
           object stored in the Pubring for that remailer.
        """
        if name is None:
            if exit:
                name = self.chain.randexit()
            else:
                name = self.chain.randany()
        rem_data = self.pubring[name]
        log.debug("Retrieved Pubkey data for: %s <%s>",
                  name, rem_data['email'])
        return rem_data


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


log = logging.getLogger("Pymaster.%s" % __name__)
if (__name__ == "__main__"):
    logfmt = config.get('logging', 'format')
    datefmt = config.get('logging', 'datefmt')
    log = logging.getLogger("Pymaster")
    log.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(fmt=logfmt, datefmt=datefmt))
    log.addHandler(handler)
    pubring = KeyManager.Pubring()
    encode = Mixmaster(pubring)
    msg = email.message.Message()
    msg['Dests'] = 'steve@mixmin.net'
    msg['Cc'] = 'mail2news@mixmin.net'
    msg['Newsgroups'] = 'news.group'
    msg['Chain'] = 'pymaster'
    msg.set_payload("Test Message")

    payload = Payload(msg)
    payload.email2payload()
    outmsg = encode.makemsg(payload)
    #encode.dummy()
