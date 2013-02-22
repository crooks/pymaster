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
import Crypto.Random
from Crypto.PublicKey import RSA
from Crypto.Hash import MD5
import timing


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

    def sec_construct(self, key):
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
        return RSA.construct(n, e, d, p, q)

    def pub_construct(self, key):
        l = struct.unpack("<H", key[0:2])[0]
        n = self.big_endian(struct.unpack('>128B', key[2:130]))
        e = self.big_endian(struct.unpack('>128B', key[130:258]))
        return RSA.construct(n, e)

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
                else:
                    key += line
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

class Keyring():
    def __init__(self):
        self.pubring = "pubring.mix"
        self.mlist2 = "mlist2.txt"

    def pubkey_import(self):
        f = open(self.pubring, 'r')
        # Bool to indicate when an actual key is being read.  Set True by
        # "Begin Mix Key" cutmarks and False by "End Mix Key" cutmarks.
        inkey = False
        # The header always preceeds the key.  The following loop doesn't
        # consider key content until a valid header has been processed.  The
        # bool is reset by the "End Mix Key" cutmarks.
        gothead = False
        for line in f:
            if not inkey and not gothead:
                header = line.rstrip().split(" ")
                if len(header) == 5 or len(header) == 7:
                    # Pubring headers contain the following elements:-
                    # header[0] Remailer Shortname
                    # header[1] Remailer Email Address
                    # header[2] Key ID
                    # header[3] Mixmaster Version
                    # header[4] Capstring
                    #
                    # Mixmaster > v3.0 also contain the following:-
                    # header[5] Valid From Date
                    # header[6] Expire Date
                    gothead = True
            elif (gothead and not inkey and
                  line.startswith("-----Begin Mix Key-----")):
                inkey = True
                line_count = 0
                b64key = ""
            elif (gothead and inkey and
                  line.startswith("-----End Mix Key-----")):
                inkey = False
                gothead = False
                key = b64key.decode("base64")
                if self._import_validate(keylen, keyid, header[2], key):
                    print "Valid"
                else:
                    print "%s: Invalid key" % header[0]
            elif gothead and inkey:
                line_count += 1
                if line_count == 1:
                    keyid = line.rstrip()
                elif line_count == 2:
                    keylen = int(line.rstrip())
                else:
                    b64key += line
            elif len(line.rstrip()) == 0:
                # We can safely ignore blank lines if none of the above
                # conditions apply.
                pass
            else:
                print "Unexpected line: %s" % line.rstrip()
        f.close()

    def _import_validate(self, keylen, keyid, headid, key):
        valid_length = len(key) == keylen
        valid_keyid = keyid == MD5.new(data=key[2:258]).hexdigest() == headid
        return valid_length and valid_keyid

    def mlist2_import(self):
        f = open(self.mlist2, 'r')
        instats = False
        for line in f:
            if line.startswith("Generated: "):
                generated = line.split(": ", 1)[1].rstrip()
            elif line.startswith("----------"):
                instats = True
            elif instats and len(line.rstrip()) == 0:
                instats = False
            elif instats:
                name = line[0:13].rstrip()
                latent = line[27:32].lstrip()
                uptime = line[49:54].lstrip()
                opts = line[57:72]
                print name, latent, uptime, opts
        f.close()

k = Keyring()
#k.pubkey_import()
k.mlist2_import()
