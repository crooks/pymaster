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
import os.path
from Crypto.Cipher import DES3, PKCS1_v1_5
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA
import Crypto.Random
import Config
import KeyManager


class ValidationError(Exception):
    pass


def des3_iv():
    return Crypto.Random.get_random_bytes(8)


def des3_key():
    return Crypto.Random.get_random_bytes(24)


def des3_encrypt(data, deskey, iv):
    assert len(deskey) == 24
    assert len(iv) == 8
    assert len(data) % 8 == 0
    desobj = DES3.new(deskey, DES3.MODE_CBC, IV=iv)
    return desobj.encrypt(data)


def des3_decrypt(data, deskey, iv):
    assert len(deskey) == 24
    assert len(iv) == 8
    assert len(data) % 8 == 0
    desobj = DES3.new(deskey, DES3.MODE_CBC, IV=iv)
    return desobj.decrypt(data)
    

def pad(length, data):
    padding = length - len(data)
    padded = data + Crypto.Random.get_random_bytes(padding)
    assert len(padded) == length
    return padded


class MixPayload():
    def set_deskey(self, deskey):
        if len(deskey) != 24:
            raise ValidationError("Session key returned incorrect length "
                                  "3DES key")
        self.deskey = deskey

    def set_inner_head(self, packet):
        """Packet ID                            [ 16 bytes]
           Triple-DES key                       [ 24 bytes]
           Packet type identifier               [  1 byte ]
           Packet information      [depends on packet type]
           Timestamp                            [  7 bytes]
           Message digest                       [ 16 bytes]
           Random padding               [fill to 328 bytes]

        Regardless of the Packet Type, this function will always return a list
        of 5 elements.  Those being, ID, 3DESkey, TypeID, Packet_info and
        Timestamp.
        The Message Digest is only used for validation within the function.
        The Packet_Info is a flexible list of elements depending on the
        TypeID.
        """
        if len(packet.decrypted) != 328:
            raise ValidationError("Incorrect number of Bytes decrypted")
        (packet_id,
         deskey,
         packet_type) = struct.unpack("@16s24sB", packet.decrypted[0:41])
        self.packet_id = packet_id
        self.set_deskey(deskey)
        if packet_type == 0:
            self.intermediate_message(packet)
        elif packet_type == 1:
            iv, msgid = self.exit_message(packet)
            desobj = DES3.new(deskey, DES3.MODE_CBC, IV=iv)
            self.unpack_body(packet, desobj)
        elif packet_type == 2:
            pass
        else:
            raise ValidationError("Unknown Packet type")


    def intermediate_message(self, packet):
        """Packet type 0 (intermediate hop):
           19 Initialization vectors      [152 bytes]
           Remailer address               [ 80 bytes]
        """
        (nineteen_ivs, addy, timestamp,
         msgdigest) = struct.unpack('@152s80s7s16s', packet.decrypted[41:296])
        # Put the IVs into individual list items, starting at header[3]
        packet_info = []
        for i in range(19):
            sbyte = i * 8
            packet_info.append(nineteen_ivs[sbyte:sbyte + 8])
        packet_info.append(addy)
        # Checksum includes everything up to the Message Digest.
        # Don't forget this needs to include the 7 Byte Timestamp!
        checksum = MD5.new(data=packet.decrypted[0:280]).digest()
        if checksum != msgdigest:
            raise ValidationError("Encrypted header failed checksum")
        #print "Intermediate Message: Next Hop: %s" % addy

    def exit_message(self, packet):
        """Packet type 1 (final hop):
           Message ID                     [ 16 bytes]
           Initialization vector          [  8 bytes]
        """
        (message_id, iv, timestamp,
         msgdigest) = struct.unpack('@16s8s7s16s', packet.decrypted[41:88])
        checksum = MD5.new(data=packet.decrypted[0:72]).digest()
        if checksum != msgdigest:
            raise ValidationError("Encrypted header failed checksum")
        return iv, message_id

    def chunk_message(self, packet):
        """Packet type 2 (final hop, partial message):
           Chunk number                   [  1 byte ]
           Number of chunks               [  1 byte ]
           Message ID                     [ 16 bytes]
           Initialization vector          [  8 bytes]
        """
        (chunk, chunks, message_id, iv, timestamp,
         msgdigest) = struct.unpack('@BB16s8s7s16s', packet.decrypted[41:90])
        packet_info = []
        packet_info.append(chunk)
        packet_info.append(chunks)
        packet_info.append(message_id)
        packet_info.append(iv)
        checksum = MD5.new(data=packet.decrypted[0:74]).digest()
        if checksum != msgdigest:
            raise ValidationError("Encrypted header failed checksum")

    """This step only needs to be performed for Exit messages.  At all other
    times, the message Body is wrapped in layers of encryption.

        Length                         [       4 bytes]
        Number of destination fields   [        1 byte]
        Destination fields             [ 80 bytes each]
        Number of header line fields   [        1 byte]
        Header lines fields            [ 80 bytes each]
        User data section              [ up to ~2.5 MB]
    """

    def unpack_body(self, packet, desobj):
        """Length                         [       4 bytes]
           Number of destination fields   [        1 byte]
           Destination fields             [ 80 bytes each]
           Number of header line fields   [        1 byte]
           Header lines fields            [ 80 bytes each]
           User data section              [ up to ~2.5 MB]
        """
        body = desobj.decrypt(packet.body)
        sbyte = 0
        ebyte = 5
        length, dfields = struct.unpack('<IB', body[sbyte:ebyte])
        dest_struct = "80s" * dfields
        sbyte = ebyte
        ebyte = sbyte + (80 * dfields)
        destlist = list(struct.unpack(dest_struct, body[sbyte:ebyte]))
        sbyte = ebyte
        ebyte = sbyte + 1
        if destlist[0].startswith("null:"):
            print "Dummy Message"
            return None, None, None
        hfields = struct.unpack('B', body[sbyte])[0]
        head_struct = "80s" * hfields
        sbyte = ebyte
        ebyte = sbyte + 80 * hfields
        headlist = list(struct.unpack(head_struct, body[sbyte:ebyte]))
        sbyte = ebyte
        # The length of the message is prepended by the 4 Byte length,
        # hence why we need to add 4 to ebyte.
        ebyte = length + 4
        print self.unpad(destlist)
        print self.unpad(headlist)

    def unpad(self, padded):
        assert type(padded) == list
        for e in range(len(padded)):
            padded[e] = padded[e].rstrip("\x00")
        return padded
                

class DecodeHeader():
    def __init__(self):
        self.sk = KeyManager.SecretKey()

    def unpack(self, packet):
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
        # encrypted component.  We can ignore the 31 Bytes of padding, hence
        # 481 Bytes instead of 512.
        mix = MixPayload()
        (keyid, datalen, sesskey, iv,
         enc) = struct.unpack('@16sB128s8s328s', packet.header[0:481])
        if not len(sesskey) == datalen:
            raise ValidationError("Incorrect session key size")
        # Use the session key to decrypt the 3DES Symmetric key
        seckey = self.sk[keyid.encode("hex")]
        if seckey is None:
            raise ValidationError("Secret Key not found")
        pkcs1 = PKCS1_v1_5.new(seckey)
        sess_deskey = pkcs1.decrypt(sesskey, "Failed")

        # Process the 328 Bytes of encrypted header using our newly discovered
        # 3DES key obtained from the pkcs1 decryption.
        desobj = DES3.new(sess_deskey, DES3.MODE_CBC, IV=iv)
        packet.decrypted = desobj.decrypt(enc)
        mix.set_inner_head(packet)
        # Unpack the 328 decrypted bytes into their component parts
        return mix


def body_test():
    msg = "This is a test message"
    dests = ["steve@mixmin.net"]
    headers = ["steve@mixmin.net"]
    b = Body()
    body = b.body_pack(msg, dests, headers)
    iv = des3_iv()
    key = des3_key()
    encrypted = des3_encrypt(body, key, iv)
    decrypted = des3_decrypt(encrypted, key, iv)
    destlist, headlist, body = b.body_unpack(decrypted)
    for d in destlist:
        print d.rstrip("\x00")
    for h in headlist:
        print h.rstrip("\x00")
    print body


config = Config.Config().config
if (__name__ == "__main__"):
    pass
