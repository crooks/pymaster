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
import random
import sys
import timing
from Crypto.Cipher import DES3, PKCS1_v1_5
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA

def padding(string, length, pad="\x00"):
    padded = string.ljust(length, pad)
    if len(padded) < len(string):
        print "Padded shorter than input!"
    return padded


class header():
    def __init__(self):
        """Public key ID                [  16 bytes]
           Length of RSA-encrypted data [   1 byte ]
           RSA-encrypted session key    [ 128 bytes]
           Initialization vector        [   8 bytes]
           Encrypted header part        [ 328 bytes]
           Padding                      [  31 bytes]
        """

        self.header_format = "@16sB128s8s328s31s"

    def unpack(self, headbytes):
        if len(headbytes) != 512:
            print "Incorrect header length: %s Bytes" % len(headbytes)
            sys.exit(1)
        (keyid, lenrsa, rsakey,
        iv, head, pad) = struct.unpack(self.header_format, headbytes)
        #des = crypto.cipher.DES3.new(decryptionkey, DES3.MODE_CBC, IV=iv)
        return lenrsa

class secret_key():
    def big_endian(self, byte_array):
        """Convert a Big-Endian Byte-Array to a long int."""
        x = long(0)
        for b in byte_array:
            x = (x << 8) + b
        return x

    def generate(self):
        k = RSA.generate(1024)
        public = k.publickey()
        secpem = k.exportKey(format='PEM')
        pubpem = public.exportKey(format='PEM')
        print secpem
        print pubpem

    def construct(self, key):
        """Take a binary Mixmaster secret key and return an RSAobj
        """
        s = ">128B"
        l = struct.unpack("<H", key[0:2])[0]
        n = self.big_endian(struct.unpack('>128B', key[2:130]))
        e = self.big_endian(struct.unpack('>128B', key[130:258]))
        d = self.big_endian(struct.unpack('>128B', key[258:386]))
        p = self.big_endian(struct.unpack('>64B', key[386:450]))
        q = self.big_endian(struct.unpack('>64B', key[450:514]))
        if n - (p * q) != 0:
            print "Invalid key structure (n - (p * q) != 0)"
            sys.exit(1)
        if p < q:
            print "Invalid key structure (p < q)"
        return RSA.construct((n, e, d, p, q))

    def read(self):
        """Read a secring.mix file and return the decryted keys.  This
        function relies on construct() to create an RSAobj.

        -----Begin Mix Key-----
        Created: yyyy-mm-dd
        Expires: yyyy-mm-dd
        KeyID (Hex Encoded)
        0
        IV (Base64 Encoded)
        Encrypted Key
        -----End Mix Key-----
        """

        f = open("/home/crooks/tmp/secring.mix")
        inkey = False
        for line in f:
            if line.startswith("-----Begin Mix Key-----"):
                if inkey:
                    print "Yikes, we got a Begin before an End!"
                    sys.exit(1)
                key = ""
                lcount = 0
                inkey = True
                continue
            if inkey:
                lcount += 1
                if lcount == 1 and line.startswith("Created:"):
                    created = timing.dateobj(line.split(": ")[1].rstrip())
                elif lcount == 2 and line.startswith("Expires:"):
                    expires = timing.dateobj(line.split(": ")[1].rstrip())
                elif lcount == 3 and len(line) == 33:
                    keyid = line.rstrip()
                elif lcount == 4:
                    continue
                elif lcount == 5:
                    iv = line.rstrip().decode("base64")
                elif line.startswith("-----End Mix Key-----"):
                    inkey = False
                    keybin = key.decode("base64")
                else: key += line
        f.close()
        #TODO Because the remainder of this code is outside the loop, only
        # the last key in the file is actually handled.

        # Hash a textual password and then use that hash, along with the
        # extracted IV, as the key for 3DES decryption.
        password = "Two Humped Dromadary"
        pwhash = MD5.new(data=password).digest()
        des = DES3.new(pwhash, DES3.MODE_CBC, IV=iv)
        decrypted_key = des.decrypt(keybin)
        # The decrypted key should always be 712 Bytes
        if len(decrypted_key) != 712:
            print "secring: Decrypted key is incorrect length!"
            sys.exit(1)
        # The 256 Byte keyid is generated from the key so we can validate
        # it here.
        if MD5.new(data=decrypted_key[2:258]).hexdigest() != keyid:
            print ("secring: Checksum failed.  Decrypted hash does not "
                   "match keyid.")
            sys.exit(1)
        return self.construct(decrypted_key)

class message():
    def __init__(self):
        """ Length                         [       4 bytes]
            Number of destination fields   [        1 byte]
            Destination fields             [ 80 bytes each]
            Number of header line fields   [        1 byte]
            Header lines fields            [ 80 bytes each]
            User data section              [ up to ~2.5 MB]
        """

        sk = secret_key()
        seckey = sk.read()
        self.pkcs1 = PKCS1_v1_5.new(seckey)

    def encrypted_header(self, decrypted):
        """Packet ID                            [ 16 bytes]
           Triple-DES key                       [ 24 bytes]
           Packet type identifier               [  1 byte ]
           Packet information      [depends on packet type]
           Timestamp                            [  7 bytes]
           Message digest                       [ 16 bytes]
           Random padding               [fill to 328 bytes]
        """

        if len(decrypted) != 328:
            print "unpack: Incorrect number of Bytes decrypted"
            sys.exit(1)
        (packetid, deskey,
         packettype, info) = struct.unpack("@16s24s1B287s", decrypted)
        if packettype == 0:
            """Packet type 0 (intermediate hop):
               19 Initialization vectors      [152 bytes]
               Remailer address               [ 80 bytes]
            """
            ivs = info[0:152]
            addy = info[152:232]
            rest = info[232:]
            print "Next Hop: %s" % addy
        elif packettype == 1:
            """Packet type 1 (final hop):
               Message ID                     [ 16 bytes]
               Initialization vector          [  8 bytes]
            """
            message_id = info[0:16]
            iv = info[16:24]
            rest = info[24:]
        elif packettype == 2:
            """Packet type 2 (final hop, partial message):
               Chunk number                   [  1 byte ]
               Number of chunks               [  1 byte ]
               Message ID                     [ 16 bytes]
               Initialization vector          [  8 bytes]
            """
            chunk = info[0]
            chunks = info[1]
            message_id = info[2:18]
            iv = info[18:26]
            rest = info[26:]
        else:
            print "Unknown Packet type"
            sys.exit(1)
        timestamp = rest[0:7]
        digest = rest[7:23]

    def unpack(self):
        """Unpack a received Mixmaster email message.

        Public key ID                [  16 bytes]
        Length of RSA-encrypted data [   1 byte ]
        RSA-encrypted session key    [ 128 bytes]
        Initialization vector        [   8 bytes]
        Encrypted header part        [ 328 bytes]
        Padding                      [  31 bytes]
        """

        src = "/home/crooks/tmp/1360506803.13262_0.snorky"
        f = open(src, 'r')
        mixmes = False
        while f:
            if f.readline().startswith("-----BEGIN REMAILER MESSAGE-----"):
                mixmes = True
                break
        if mixmes:
            length = int(f.readline())
            digest = f.readline().rstrip().decode("base64")
            packet = f.read().decode("base64")
        f.close()
        if length != len(packet):
            print "Message unpack: Stated packet length is incorrect"
            sys.exit(1)
        if digest != MD5.new(data=packet).digest():
            print "Message unpack: Checksum failed"
            sys.exit(1)
        header = packet[:512]
        header_format = "@16sB128s8s328s31s"
        (keyid, datalen, sesskey,
         iv, enc, pad) = struct.unpack(header_format, header)
        # Use the session key to decrypt the 3DES Symmetric key
        deskey = self.pkcs1.decrypt(sesskey, "Failed")
        # Now use the decrypted 3DES key to decrypt the 328 Bytes
        des = DES3.new(deskey, DES3.MODE_CBC, IV=iv)
        data = des.decrypt(enc)
        self.encrypted_header(data)

def randbytes(n):
    b = ''.join(chr(random.randint(0,255)) for _ in range(n))
    return b

#h = header()
#teststr = randbytes(512):q
#print len(teststr)
#result = h.unpack(teststr)
#print result

m = message()
m.unpack()
