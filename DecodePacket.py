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
import os
import os.path
import logging
import email.message
from Crypto.Cipher import DES3, PKCS1_v1_5
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA
import Crypto.Random
from Config import config
import EncodePacket
import KeyManager
import Chain
import Utils


class ValidationError(Exception):
    pass


class DummyMessage(Exception):
    pass


class DestinationError(Exception):
    """Raised when a Middleman remailer doesn't explicitly accept a stated
    destination"""
    pass


class MixPacket():
    def set_headers(self, headers):
        self.headers = headers

    def set_encbody(self, encbody):
        self.encbody = encbody

    def set_dhead(self, dhead):
        self.dhead = dhead

    def set_dbody(self, dbody):
        self.dbody = dbody


class Mixmaster():
    def __init__(self):
        self.destalw = ConfFiles(config.get('etc', 'dest_alw'), 'dest_alw')
        self.destblk = ConfFiles(config.get('etc', 'dest_blk'), 'dest_blk')
        self.middleman = config.getboolean('general', 'middleman')
        self.randhop = EncodePacket.RandHop()

    def process(self, packet):
        self.msg = email.message.Message()
        # Decrypt the 328 byte Encrypted Header
        self.packet_decrypt(packet)
        try:
            self.unpack(packet)
        except DestinationError:
            self.msg = self.randhop.randhop(packet)
        return self.msg

    def packet_decrypt(self, packet):
        """Unpack a received Mixmaster email message header.  The spec calls
        for 512 Bytes, of which the last 31 are padding.

           Public key ID                [  16 bytes]
           Length of RSA-encrypted data [   1 byte ]
           RSA-encrypted session key    [ 128 bytes]
           Initialization vector        [   8 bytes]
           Encrypted header part        [ 328 bytes]
           Padding                      [  31 bytes]

        """
        # Unpack the header components.  This includes the 328 Byte
        # encrypted component.
        (keyid, datalen, sesskey, iv, enc,
         pad) = struct.unpack('@16sB128s8s328s31s', packet.headers[0])
        if not len(sesskey) == datalen:
            raise ValidationError("Incorrect session key size")
        keyid = keyid.encode("hex")
        log.debug("Message is encrypted to key: %s", keyid)
        # Use the session key to decrypt the 3DES Symmetric key
        seckey = secring[keyid]
        if seckey is None:
            raise ValidationError("Secret Key not found")
        pkcs1 = PKCS1_v1_5.new(seckey)
        deskey = pkcs1.decrypt(sesskey, "Failed")
        # Process the 328 Bytes of encrypted header using our newly discovered
        # 3DES key obtained from the pkcs1 decryption.
        desobj = DES3.new(deskey, DES3.MODE_CBC, IV=iv)
        packet.set_dhead(desobj.decrypt(enc))

    def unpack(self, packet):
        """Packet ID                            [ 16 bytes]
           Triple-DES key                       [ 24 bytes]
           Packet type identifier               [  1 byte ]
           Packet information      [depends on packet type]
           Timestamp                            [  7 bytes]
           Message digest                       [ 16 bytes]
           Random padding               [fill to 328 bytes]
        """
        assert len(packet.dhead) == 328
        (packet_id,
         deskey,
         packet_type) = struct.unpack("@16s24sB", packet.dhead[0:41])
        if packet_type == 0:
            """Packet type 0 (intermediate hop):
               19 Initialization vectors      [152 bytes]
               Remailer address               [ 80 bytes]
            """
            log.debug("Message is of intermediate type.")
            self.validate(packet, 273)
            fmt = "@" + ("8s" * 19)
            ivs = struct.unpack(fmt, packet.dhead[41:193])
            addy = packet.dhead[193:273].rstrip("\x00")
            log.debug("Next hop is: %s", addy)
            self.msg.add_header("To", addy)
            # The payload string will be extended as each header has a layer of
            # encryption striped off.
            payload = ""
            # Loop through two components of the message, in parallel. The IVs
            # are extracted from the encrypted packet and the corresponding
            # encrypted header has a layer of 3DES removed.
            assert len(ivs) == 19
            assert len(packet.headers) == 20
            for h in range(19):
                # Decrypt each 512 Byte packet header using the 3DES key and a
                # sequence of IVs held in the packet information.
                desobj = DES3.new(deskey, DES3.MODE_CBC, IV=ivs[h])
                payload += desobj.decrypt(packet.headers[h + 1])
            # At this point, the payload contains 19 headers so the length
            # should be 19 * 512 Bytes.
            assert len(payload) == 9728
            # Add a fake 512 byte header to the bottom of the header stack.
            # This replaces the first header that we removed.
            payload += Crypto.Random.get_random_bytes(512)
            assert len(payload) == 10240
            payload += desobj.decrypt(packet.encbody)
            assert len(payload) == 20480
            self.msg.set_payload(self.mixprep(payload))
        elif packet_type == 1:
            """Packet type 1 (final hop):
               Message ID                     [ 16 bytes]
               Initialization vector          [  8 bytes]
            """
            log.debug("This is an Exit type message")
            self.validate(packet, 65)
            message_id, iv = struct.unpack("@16s8s", packet.dhead[41:65])
            """Length                         [       4 bytes]
               Number of destination fields   [        1 byte]
               Destination fields             [ 80 bytes each]
               Number of header line fields   [        1 byte]
               Header lines fields            [ 80 bytes each]
               User data section              [ up to ~2.5 MB]
            """
            desobj = DES3.new(deskey, DES3.MODE_CBC, IV=iv)
            packet.set_dbody(desobj.decrypt(packet.encbody))
            sbyte = 0
            ebyte = 5
            length, dfields = struct.unpack('<IB', packet.dbody[sbyte:ebyte])
            dest_struct = "80s" * dfields
            sbyte = ebyte
            ebyte = sbyte + (80 * dfields)
            destlist = list(struct.unpack(dest_struct,
                            packet.dbody[sbyte:ebyte]))
            if destlist[0].startswith("null:"):
                raise DummyMessage("Dummy message")
            dests = self.dest_allow(destlist)
            if len(dests) == 0:
                raise ValidationError("No acceptable destinations for this "
                                      "message")
            desthead = ','.join(dests)
            self.msg.add_header("To", desthead)
            # At this point we have established a list of acceptable
            # email destinations.
            sbyte = ebyte
            ebyte = sbyte + 1
            hfields = struct.unpack('B', packet.dbody[sbyte])[0]
            head_struct = "80s" * hfields
            sbyte = ebyte
            ebyte = sbyte + 80 * hfields
            headlist = list(struct.unpack(head_struct,
                                          packet.dbody[sbyte:ebyte]))
            heads = self.unpad(headlist)
            for h in heads:
                head, content = h.split(": ", 1)
                self.msg.add_header(head, content)
                log.debug("Defined outbound header (%s: %s)", head, content)
            sbyte = ebyte
            # The length of the message is prepended by the 4 Byte length,
            # hence why we need to add 4 to ebyte.
            ebyte = length + 4
            self.msg.set_payload(packet.dbody[sbyte:ebyte])
        elif packet_type == 2:
            """Packet type 2 (final hop, partial message):
               Chunk number                   [  1 byte ]
               Number of chunks               [  1 byte ]
               Message ID                     [ 16 bytes]
               Initialization vector          [  8 bytes]
            """
            log.debug("This is a chunk-type message")
            self.validate(packet, 67)

    def chunk_message(self, packet):
        """Packet type 2 (final hop, partial message):
           Chunk number                   [  1 byte ]
           Number of chunks               [  1 byte ]
           Message ID                     [ 16 bytes]
           Initialization vector          [  8 bytes]
        """
        (chunk, chunks, message_id, iv, timestamp,
         msgdigest) = struct.unpack('@BB16s8s7s16s',
                                    packet['decrypted'][41:90])
        packet_info = []
        packet_info.append(chunk)
        packet_info.append(chunks)
        packet_info.append(message_id)
        packet_info.append(iv)
        checksum = MD5.new(data=packet['decrypted'][0:74]).digest()
        if checksum != msgdigest:
            raise ValidationError("Encrypted header failed checksum")

    def validate(self, packet, sbyte):
        """Encrypted headers are of varying length depending on type (Exit,
        Intermediate or Chunk).  This function validates the timestamp and
        digest on these types based on the provided sbyte index.
        """
        ebyte = sbyte + 5
        timehead = struct.unpack("5s", packet.dhead[sbyte:ebyte])[0]
        if timehead != "0000\x00":
            raise ValidationError("Timestamp not where expected")
        sbyte = ebyte
        ebyte = sbyte + 2
        timestamp = struct.unpack("<H", packet.dhead[sbyte:ebyte])[0]
        # The checksum covers the entire packet up to and including the
        # timestamp.
        checksum = MD5.new(data=packet.dhead[0:ebyte]).digest()
        sbyte = ebyte
        ebyte = sbyte + 16
        digest = packet.dhead[sbyte:ebyte]
        if digest != checksum:
            raise ValidationError("Encrypted header failed checksum")

    def unpad(self, padded):
        """Strip trailing Hex 00 from all the elements of a list."""
        assert type(padded) == list
        for e in range(len(padded)):
            padded[e] = padded[e].rstrip("\x00")
        return padded

    def mixprep(self, binary):
        """Take a binary string, encode it as Base64 and wrap it to lines of
           length n.
        """
        # This is the wrap width for Mixmaster Base64
        n = 40
        s = binary.encode("base64")
        s = ''.join(s.split("\n"))
        payload = "::\n"
        payload += "Remailer-Type: %s\n\n" % config.get('general', 'version')
        payload += "-----BEGIN REMAILER MESSAGE-----\n"
        while len(s) > 0:
            payload += s[:n] + "\n"
            s = s[n:]
        payload += "-----END REMAILER MESSAGE-----\n"
        return payload

    def dest_allow(self, dests):
        """Read the list of destinations defined in the message.  Strip out
        any that are explicitly blocked and return a new list of allowed
        destinations.  If any one is not explicitly allowed and we're running
        as a Middleman, raise a DestinationError and randhop it.
        """
        alw_dests = []
        randhop = False
        for d in self.unpad(dests):
            alw = self.destalw.hit(d)
            blk = self.destblk.hit(d)
            if alw and not blk:
                alw_dests.append(d)
            elif blk and not alw:
                log.info("%s: Destination explicitly blocked.", d)
            elif blk and alw:
                # Both allow and block hits mean a decision has to be made on
                # which has priority.  If block_first is True then allow is the
                # second (most significant) check.  If it's False, block is
                # more significant and the destinaion is not allowed.
                if config.getboolean('general', 'block_first'):
                    alw_dests.append(d)
                else:
                    log.info("%s: Dest matches allow and block rules but "
                             "configuration dictates that block takes "
                             "priority", d)
            # Any blocked destination shouldn't reach this point.
            elif self.middleman and not alw:
                # The dest is not explicitly allowed or denied.  As this is
                # a Middleman.
                log.info("%s: Middleman doesn't allow this destination.", d)
                raise DestinationError("Must randhop")
            else:
                # No explict allow rule but we're not a Middleman so accept
                # the stated destination.
                alw_dests.append(d)
        return alw_dests


class ConfFiles():
    def __init__(self, filename, name):
        # mtime is set to the Modified date on the file in "since Epoch"
        # format.  Setting it to zero ensures the file is read on the first
        # pass.
        mtime = 0
        self.mtime = mtime
        self.filename = filename

    def hit(self, testdata):
        if not os.path.isfile(self.filename):
            return False
        file_modified = os.path.getmtime(self.filename)
        if file_modified > self.mtime:
            (self.regex_rules,
             self.list_rules) = Utils.file2regex(self.filename)
            self.mtime = file_modified
        if testdata in self.list_rules:
            log.debug("Message matches: %s", testdata)
            return True
        if self.regex_rules:
            regex_test = self.regex_rules.search(testdata)
            if regex_test:
                log.debug("Message matches Regular Expression: %s",
                         regex_test.group(0))
                return True
        return False


log = logging.getLogger("Pymaster.%s" % __name__)
secring = KeyManager.Secring()
pubring = KeyManager.Pubring()
chain = Chain.Chain()
if (__name__ == "__main__"):
    logfmt = config.get('logging', 'format')
    datefmt = config.get('logging', 'datefmt')
    log = logging.getLogger("Pymaster")
    log.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(fmt=logfmt, datefmt=datefmt))
    log.addHandler(handler)
