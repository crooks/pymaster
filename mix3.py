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
import os.path
import timing
from Crypto.Cipher import DES3, PKCS1_v1_5
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA

class secret_key():
    def big_endian(self, byte_array):
        """Convert a Big-Endian Byte-Array to a long int."""
        x = long(0)
        for b in byte_array:
            x = (x << 8) + b
        return x

    def pem_export(self, keyobj, fn):
        public = keyobj.publickey()
        secpem = keyobj.exportKey(format='PEM')
        pubpem = public.exportKey(format='PEM')
        f = open(fn, 'w')
        f.write(secpem)
        f.write("\n\n")
        f.write(pubpem)
        f.write("\n")
        f.close()

    def pem_import(self, fn):
        if not os.path.isfile(fn):
            print "PEM Import: %s file not found"
            sys.exit(1)
        f = open(fn, 'r')
        pem = f.read()
        return RSA.importKey(pem)

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

    def read_secring(self):
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
        #seckey = sk.read_secring()
        #sk.pem_export(seckey, "keys.pem")
        seckey = sk.pem_import("keys.pem")
        self.pkcs1 = PKCS1_v1_5.new(seckey)

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
        desobj = DES3.new(deskey, DES3.MODE_CBC, IV=iv)
        self.encrypted_header(desobj, enc)
        headers = []
        # Decrypt each of the remaining 19 512Byte headers using the session
        # key we got from the first header.
        for h in range(19):
            sbyte = (h + 1) * 512
            headers.append(desobj.decrypt(packet[sbyte:sbyte + 512]))

    def encrypted_header(self, desobj, encrypted):
        """Packet ID                            [ 16 bytes]
           Triple-DES key                       [ 24 bytes]
           Packet type identifier               [  1 byte ]
           Packet information      [depends on packet type]
           Timestamp                            [  7 bytes]
           Message digest                       [ 16 bytes]
           Random padding               [fill to 328 bytes]
        """
        decrypted = desobj.decrypt(encrypted)
        if len(decrypted) != 328:
            print "unpack: Incorrect number of Bytes decrypted"
            sys.exit(1)
        (packetid, deskey,
         packettype) = struct.unpack("@16s24s1B", decrypted[0:41])
        if packettype == 0:
            """Packet type 0 (intermediate hop):
               19 Initialization vectors      [152 bytes]
               Remailer address               [ 80 bytes]
            """
            (ivs, addy, timestamp,
             msgdigest) = struct.unpack('@152s80s7s16s', decrypted[41:296])
            # Checksum includes everything up to the Message Digest.
            # Don't forget this needs to include the 7 Byte Timestamp!
            checksum = MD5.new(data=decrypted[0:280]).digest()
            print "Next Hop: %s" % addy
        elif packettype == 1:
            """Packet type 1 (final hop):
               Message ID                     [ 16 bytes]
               Initialization vector          [  8 bytes]
            """
            (message_id, iv, timestamp,
             msgdigest) = struct.unpack('@16s8s7s16s', decrypted[41:88])
            checksum = MD5.new(data=decrypted[0:72]).digest()
        elif packettype == 2:
            """Packet type 2 (final hop, partial message):
               Chunk number                   [  1 byte ]
               Number of chunks               [  1 byte ]
               Message ID                     [ 16 bytes]
               Initialization vector          [  8 bytes]
            """
            (chunk, chunks, message_id, iv, timestamp,
             msgdigest) = struct.unpack('@BB16s8s7s16s', decrypted[41:90])
            checksum = MD5.new(data=decrypted[0:74]).digest()
        else:
            print "Unknown Packet type"
            sys.exit(1)
        if checksum != msgdigest:
            print "Encrypted message component failed checksum"
            sys.exit(1)

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
