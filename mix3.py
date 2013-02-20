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
import mailbox
from Crypto.Cipher import DES3, PKCS1_v1_5
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA
import Crypto.Random
import timing
from Config import config
import ConfigFiles

class ValidationError(Exception):
    pass

class secret_key():
    def test(self):
        """ This test demonstrates why Mixmaster cannot use bigger RSA keys.
        If the key size is increased from 1024 to 2048 Bytes, the 24 Byte
        session key, when encrypted, would increase from 128 to 256 Bytes.
        The encrypted session key is contained within the plain-text component
        of each 512 message header and only has 128 Bytes allocated to it.
        """

        deskey = Crypto.Random.get_random_bytes(24)
        pkcs1_key = self.generate(keysize=2048)
        pkcs1 = PKCS1_v1_5.new(pkcs1_key)
        sesskey = pkcs1.encrypt(deskey)
        print len(sesskey)

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
            print "PEM Import: %s file not found" % fn
            sys.exit(1)
        f = open(fn, 'r')
        pem = f.read()
        return RSA.importKey(pem)

    def generate(self, keysize=1024):
        k = RSA.generate(keysize)
        public = k.publickey()
        secpem = k.exportKey(format='PEM')
        pubpem = public.exportKey(format='PEM')
        return k

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

    def read_secring(self, secring):
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

        f = open(secring)
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
        sk = secret_key()
        #seckey = sk.read_secring()
        #sk.pem_export(seckey, "keys.pem")
        seckey = sk.pem_import(config.get('keys', 'seckey'))
        self.pkcs1 = PKCS1_v1_5.new(seckey)
        self.inbox = mailbox.Maildir(config.get('paths', 'maildir'),
                                     factory=None, create=False)
        self.alw = ConfigFiles.Parser(config.get('etc', 'dest_alw'))
        self.blk = ConfigFiles.Parser(config.get('etc', 'dest_blk'))

    def process_mailbox(self):
        # Iterate over each message in the inbox.  This loop effectively
        # envelops all processing.
        for key in self.inbox.iterkeys():
            try:
                self.mailbox_message(key)
            except ValidationError, e:
                print e

    def mailbox_message(self, key):
        """-----BEGIN REMAILER MESSAGE-----
           [packet length ]
           [message digest]
           [encoded packet]
           -----END REMAILER MESSAGE-----
        """

        msgtxt = self.inbox.get_string(key)
        mixmes = False
        for line in msgtxt.split("\n"):
            if line.startswith("-----BEGIN REMAILER MESSAGE-----"):
                if mixmes:
                    raise ValidationError("Corrupted. Got multiple Begin "
                                          "Message cutmarks.")
                else:
                    # This is the beginning of a Mixmaster message.  The
                    # following variables are reset once a message is
                    # identified as a candidate.
                    mixmes = True # True when inside a Mixmaster payload
                    line_index = 0 # Packet line counter
                    packet = "" # Packet payload (in Base64)
                    continue
            if mixmes:
                line_index += 1
                if line_index == 1:
                    # Message length in Decimal
                    length = int(line)
                elif line_index == 2:
                    #Message Digest in Base64
                    digest = line.decode("base64")
                elif line.startswith("-----END REMAILER MESSAGE-----"):
                    # We don't care what comes after the End Cutmarks
                    break
                else:
                    # Append a Base64 line to the packet.
                    packet += line
        if not mixmes:
            # There is no Begin Cutmark in the message.  Not an issue.  Just
            # means this isn't a Mixmaster message.
            raise ValidationError("EOF without Begin Cutmark.")
        packet = packet.decode("base64")
        # Validate the length and digest of the packet.
        if length != len(packet):
            raise ValidationError("Incorrect packet Length")
        if digest != MD5.new(data=packet).digest():
            raise ValidationError("Mixmaster message digest failed")
        # Pass the list of message parts on for further processing.
        headers = self.first_header(packet[0:481])
        assert type(headers) == list
        if headers[2] == 0:
            self.intermediate_message(headers,
                                      packet[512:10240],
                                      packet[10240:])
        elif headers[2] == 1:
            result = self.final_message(headers, packet[10240:])
        elif headers[2] == 2:
            self.partial_final(headers)
        else:
            raise ValidationError("Unknown packet type identifier")

    def intermediate_message(self, headers, headbytes, bodybytes):
        # headers[3] is a list of the packet information component.  The last
        # element of that list is the next hop address.
        nexthop = headers[3].pop()
        # headers[1] is the 24 Byte Symmetric 3DES key required to decrypt all
        # the remaining packet headers.
        deskey = headers[1]
        head_string = ""
        # Decrypt each 512 Byte packet header using the 3DES key and a sequence
        # of IVs held in the packet information.
        for n in range(19):
            sbyte = n * 512
            desobj = DES3.new(deskey, DES3.MODE_CBC, IV=headers[3][n])
            head_string += desobj.decrypt(headbytes[sbyte:sbyte + 512])
        # Add a fake 512 byte header to the bottom of the header stack. This
        # replaces the first header that we removed.
        head_string += Crypto.Random.get_random_bytes(512)
        if len(head_string) != 10240:
            raise Exception("Incorrect header length: %s"
                             % len(head_string))
        # The message body uses the same 3DES key and IV as the last header/
        # As we already have a desobj for this, it's easy!
        head_string += desobj.decrypt(bodybytes)
        if len(head_string) != 20480:
            raise Exception("Incorrect outbound Byte length: %s"
                                   % len(head_string))

    def final_message(self, headers, encbody):
        """ Length                         [       4 bytes]
            Number of destination fields   [        1 byte]
            Destination fields             [ 80 bytes each]
            Number of header line fields   [        1 byte]
            Header lines fields            [ 80 bytes each]
            User data section              [ up to ~2.5 MB]
        """
        deskey = headers[1]
        mid = headers[3][0]
        iv = headers[3][1]
        desobj = DES3.new(deskey, DES3.MODE_CBC, IV=iv)
        body = desobj.decrypt(encbody)
        sbyte = 0
        ebyte = 5
        length,dfields = struct.unpack('<IB', body[sbyte:ebyte])
        dests = "80s" * dfields
        sbyte = ebyte
        ebyte = sbyte + (80 * dfields)
        destlist = struct.unpack(dests, body[sbyte:ebyte])
        sbyte = ebyte
        ebyte = sbyte + 1
        if destlist[0].startswith("null:"):
            #print "Dummy Message"
            pass
        else:
            hfields = struct.unpack('B', body[sbyte])[0]
            heads = "80s" * hfields
            sbyte = ebyte
            ebyte = sbyte + 80 * hfields
            headlist = struct.unpack(heads, body[sbyte:ebyte])
            sbyte = ebyte
            # The length of the message is prepended by the 4 Byte length,
            # hence why we need to add 4 to ebyte.
            ebyte = length + 4
            #print body[sbyte:length + 4]
            print "Begin Message"
            for d in destlist:
                print "Destination: %s" % d.rstrip("\x00")
            for h in headlist:
                print "Header: %s" % d.rstrip("\x00")
            print "End Message"
            blk = self.blk.validate(destlist)
            alw = self.alw.validate(destlist)
            if config.get('general', 'middleman'):
                if not alw or (alw and blk):
                    print "%s/%s: Middleman Blocked Dest" % (alw, blk)
                    raise ValidationError("Dest Blocked, need to remix")
            else:
                if blk and not alw:
                    print "%s/%s: Blocked and not Allowed" % (alw, blk)
                    raise ValidationError("Dest Blocked, need to remix")


    def first_header(self, first_header_bytes):
        """Unpack a received Mixmaster email message.

           Public key ID                [  16 bytes]
           Length of RSA-encrypted data [   1 byte ]
           RSA-encrypted session key    [ 128 bytes]
           Initialization vector        [   8 bytes]
           Encrypted header part        [ 328 bytes]
           Padding                      [  31 bytes]

        Regardless of the Packet Type, this function will always return a list
        of 5 elements.  Those being, ID, 3DESkey, TypeID, Packet_info and
        Timestamp.
        The Message Digest is only used for validation within the function.
        The Packet_Info is a flexible list of elements depending on the
        TypeID.
        """
        # Unpack the header components.  This includes the 328 Byte
        # encrypted component.  We can ignore the 31 Bytes of padding, hence
        # 481 Bytes instead of 512.
        (keyid, datalen, sesskey, iv,
         enc) = struct.unpack('@16sB128s8s328s', first_header_bytes)
        # Use the session key to decrypt the 3DES Symmetric key
        deskey = self.pkcs1.decrypt(sesskey, "Failed")
        if len(deskey) != 24:
            print "KeyID: %s" % keyid.encode("hex")
            print "Data Length: %s" % int(datalen)
            print "Session Key: %s" % sesskey.encode("hex")
            print "IV: %s" % iv.encode("hex")
            print "3DES Key=%s, Length=%s" % (deskey.encode("hex"),
                                              len(deskey))
            raise ValidationError("Session key returned incorrect length "
                                  "3DES key")
        # Process the 328 Bytes of encrypted header using our newly discovered
        # 3DES key obtained from the pkcs1 decryption.
        desobj = DES3.new(deskey, DES3.MODE_CBC, IV=iv)
        decrypted = desobj.decrypt(enc)
        """Packet ID                            [ 16 bytes]
           Triple-DES key                       [ 24 bytes]
           Packet type identifier               [  1 byte ]
           Packet information      [depends on packet type]
           Timestamp                            [  7 bytes]
           Message digest                       [ 16 bytes]
           Random padding               [fill to 328 bytes]
        """
        if len(decrypted) != 328:
            raise ValidationError("Incorrect number of Bytes decrypted")
        header = list(struct.unpack("@16s24sB", decrypted[0:41]))
        if header[2] == 0:
            """Packet type 0 (intermediate hop):
               19 Initialization vectors      [152 bytes]
               Remailer address               [ 80 bytes]
            """
            (nineteen_ivs, addy, timestamp,
             msgdigest) = struct.unpack('@152s80s7s16s', decrypted[41:296])
            # Put the IVs into individual list items, starting at header[3]
            packet_info = []
            for i in range(19):
                sbyte = i * 8
                packet_info.append(nineteen_ivs[sbyte:sbyte + 8])
            packet_info.append(addy)
            header.append(packet_info)
            header.append(timestamp)
            # Checksum includes everything up to the Message Digest.
            # Don't forget this needs to include the 7 Byte Timestamp!
            checksum = MD5.new(data=decrypted[0:280]).digest()
            #print "Next Hop: %s" % addy
        elif header[2] == 1:
            """Packet type 1 (final hop):
               Message ID                     [ 16 bytes]
               Initialization vector          [  8 bytes]
            """
            (message_id, iv, timestamp,
             msgdigest) = struct.unpack('@16s8s7s16s', decrypted[41:88])
            packet_info = []
            packet_info.append(message_id)
            packet_info.append(iv)
            header.append(packet_info)
            header.append(timestamp)
            checksum = MD5.new(data=decrypted[0:72]).digest()
        elif header[2] == 2:
            """Packet type 2 (final hop, partial message):
               Chunk number                   [  1 byte ]
               Number of chunks               [  1 byte ]
               Message ID                     [ 16 bytes]
               Initialization vector          [  8 bytes]
            """
            (chunk, chunks, message_id, iv, timestamp,
             msgdigest) = struct.unpack('@BB16s8s7s16s', decrypted[41:90])
            packet_info = []
            packet_info.append(chunk)
            packet_info.append(chunks)
            packet_info.append(message_id)
            packet_info.append(iv)
            header.append(packet_info)
            header.append(timestamp)
            checksum = MD5.new(data=decrypted[0:74]).digest()
        else:
            raise ValidationError("Unknown Packet type")
        if checksum != msgdigest:
            raise ValidationError("Encrypted header failed checksum")
        if len(header) != 5:
            raise ValidationError("Incorrect number of decrypted headers")
        return header

m = message()
m.process_mailbox()
