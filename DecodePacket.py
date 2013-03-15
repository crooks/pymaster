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
import shelve
import logging
from Crypto.Cipher import DES3, PKCS1_v1_5
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA
import Crypto.Random
from Config import config
import KeyManager
import Utils


log = logging.getLogger("Pymaster.DecodePacket")


class ValidationError(Exception):
    pass


class DummyMessage(Exception):
    pass


class MixPayload():
    def __init__(self):
        self.sk = KeyManager.SecretKey()

    def encrypted_head(self, packet):
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
        if len(packet['decrypted']) != 328:
            raise ValidationError("Incorrect number of Bytes decrypted")
        (packet_id,
         deskey,
         packet_type) = struct.unpack("@16s24sB", packet['decrypted'][0:41])
        if len(deskey) != 24:
            raise ValidationError("Session key returned incorrect length "
                                  "3DES key")
        if packet_type == 0:
            self.intermediate_message(packet, deskey)
        elif packet_type == 1:
            iv, msgid = self.exit_message(packet)
            desobj = DES3.new(deskey, DES3.MODE_CBC, IV=iv)
            self.unpack_body(packet, desobj)
        elif packet_type == 2:
            pass
        else:
            raise ValidationError("Unknown Packet type")

    def intermediate_message(self, packet, deskey):
        """Packet type 0 (intermediate hop):
           19 Initialization vectors      [152 bytes]
           Remailer address               [ 80 bytes]
        """
        # The following unpack handles elements outside the scope of the
        # intermediate packet.  This is because the intermediate components
        # vary in length, depending on message type.
        (nineteen_ivs, addy, timestamp,
         msgdigest) = struct.unpack('@152s80s7s16s',
                                    packet['decrypted'][41:296])
        # Checksum includes everything up to the Message Digest.
        # Don't forget this needs to include the 7 Byte Timestamp!
        checksum = MD5.new(data=packet['decrypted'][0:280]).digest()
        if checksum != msgdigest:
            raise ValidationError("Encrypted header failed checksum")
        # The payload string will be extended as each header has a layer of
        # encryption striped off.  Finally, the decrypted body is also added.
        payload = ""
        # Loop through two components of the message, in parallel. The IVs are
        # extracted from the encrypted packet and the corresponding encrypted
        # header has a layer of 3DES removed.
        for h in range(19):
            iv_sbyte = h * 8
            iv_ebyte = iv_sbyte + 8
            iv = nineteen_ivs[iv_sbyte:iv_ebyte]
            # Decrypt each 512 Byte packet header using the 3DES key and a
            # sequence of IVs held in the packet information.
            sbyte = h * 512
            ebyte = sbyte + 512
            desobj = DES3.new(deskey, DES3.MODE_CBC, IV=iv)
            payload += desobj.decrypt(packet['headers'][sbyte:ebyte])
        # At this point, the payload contains 19 headers so the length should
        # be 19 * 512 Bytes.
        assert len(payload) == 9728
        # Add a fake 512 byte header to the bottom of the header stack. This
        # replaces the first header that we removed.
        payload += Crypto.Random.get_random_bytes(512)
        assert len(payload) == 10240
        payload += desobj.decrypt(packet['body'])
        assert len(payload) == 20480
        f = open(Utils.poolfn('m'), 'w')
        f.write("To: %s\n\n" % addy.rstrip("\x00"))
        f.write("::\n")
        f.write("Remailer-Type: %s\n\n" % config.get('general', 'version'))
        f.write("-----BEGIN REMAILER MESSAGE-----\n")
        f.write("%s\n" % len(payload))
        f.write("%s\n" % MD5.new(data=payload).hexdigest())
        f.write(self.b64wrap(payload, 40) + "\n")
        f.write("-----END REMAILER MESSAGE-----\n")
        f.close()

    def exit_message(self, packet):
        """Packet type 1 (final hop):
           Message ID                     [ 16 bytes]
           Initialization vector          [  8 bytes]
        """
        (message_id, iv, timestamp,
         msgdigest) = struct.unpack('@16s8s7s16s', packet['decrypted'][41:88])
        checksum = MD5.new(data=packet['decrypted'][0:72]).digest()
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
        body = desobj.decrypt(packet['body'])
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
            raise DummyMessage("Don't panic!")
        hfields = struct.unpack('B', body[sbyte])[0]
        head_struct = "80s" * hfields
        sbyte = ebyte
        ebyte = sbyte + 80 * hfields
        headlist = list(struct.unpack(head_struct, body[sbyte:ebyte]))
        sbyte = ebyte
        # The length of the message is prepended by the 4 Byte length,
        # hence why we need to add 4 to ebyte.
        ebyte = length + 4
        dests = ','.join(self.unpad(destlist))
        heads = self.unpad(headlist)
        f = open(Utils.poolfn('e'), 'w')
        f.write("To: %s\n\n" % dests)
        f.write(body[sbyte:ebyte])
        f.close()

    def unpad(self, padded):
        assert type(padded) == list
        for e in range(len(padded)):
            padded[e] = padded[e].rstrip("\x00")
        return padded

    def b64wrap(self, binary, n):
        """Take a binary string, encode it as Base65 and wrap it to lines of
           length n.
        """
        s = binary.encode("base64")
        s = ''.join(s.split("\n"))
        multiline = ""
        while len(s) > 0:
            multiline += s[:n] + "\n"
            s = s[n:]
        return multiline.rstrip()

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
        (keyid, datalen, sesskey, iv,
         enc) = struct.unpack('@16sB128s8s328s', packet['header'][0:481])
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
        packet['decrypted'] = desobj.decrypt(enc)
        self.encrypted_head(packet)


if (__name__ == "__main__"):
    test = MixPayload()
