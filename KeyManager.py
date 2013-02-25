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
import Crypto.Util.number
from Crypto.PublicKey import RSA
from Crypto.Hash import MD5
from Crypto.Cipher import DES3
import timing
import Config


class KeyUtils():
    def wrap(self, s, n):
        """Take a string and wrap it to lines of length n.
        """
        s = ''.join(s.split("\n"))
        multiline = ""
        while len(s) > 0:
            multiline += s[:n] + "\n"
            s = s[n:]
        return multiline.rstrip()

    def pem_export(self, keyobj, fn):
        pem = keyobj.exportKey(format='PEM')
        f = open(fn, 'w')
        f.write(pem)
        f.write("\n")
        f.close()

    def pem_import(self, fn):
        if not os.path.isfile(fn):
            raise Exception("%s: PEM import file not found" % fn)
        f = open(fn, 'r')
        pem = f.read()
        f.close()
        return RSA.importKey(pem)

class SecretKey(KeyUtils):
    def __init__(self):
        secring = config.get('keys', 'secring')
        if not os.path.isfile(secring):
            raise Exception("%s: Secring file not found" % secring)
        self.secring = secring

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

    def generate(self, keysize=1024):
        k = RSA.generate(keysize)
        public = k.publickey()
        secpem = k.exportKey(format='PEM')
        pubpem = public.exportKey(format='PEM')
        return k

    def sec_construct(self, key):
        """Take a binary Mixmaster secret key and return an RSAobj
        """
        length = struct.unpack("<H", key[0:2])[0]
        n = Crypto.Util.number.bytes_to_long(key[2:130])
        e = Crypto.Util.number.bytes_to_long(key[130:258])
        d = Crypto.Util.number.bytes_to_long(key[258:386])
        p = Crypto.Util.number.bytes_to_long(key[386:450])
        q = Crypto.Util.number.bytes_to_long(key[450:514])
        assert n - (p * q) == 0
        assert p >= q
        rsaobj = RSA.construct((n, e, d, p, q))
        assert rsaobj.size() == length - 1
        return rsaobj

    def sec_deconstruct(self, keyobj):
        # The key length is always 1024 bits
        mix = struct.pack('<H', 1024)
        assert len(mix) == 2
        # n should always be 128 Bytes so don't try to pad it.  This
        # would just trick the assertion.
        mix += Crypto.Util.number.long_to_bytes(keyobj.n)
        assert len(mix) == 2 + 128
        mix += Crypto.Util.number.long_to_bytes(keyobj.e, blocksize=128)
        assert len(mix) == 2 + 128 + 128
        mix += Crypto.Util.number.long_to_bytes(keyobj.d)
        assert len(mix) == 2 + 128 + 128 + 128
        mix += Crypto.Util.number.long_to_bytes(keyobj.p)
        assert len(mix) == 2 + 128 + 128 + 128 + 64
        mix += Crypto.Util.number.long_to_bytes(keyobj.q)
        assert len(mix) == 2 + 128 + 128 + 128 + 64 + 64
        return self.wrap(mix.encode("base64"), 40)
        
        
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

        f = open(self.secring)
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
        return keyid, decrypted_key


class PubkeyError(Exception):
    pass


class PublicKey(KeyUtils):
    def __init__(self):
        pubring = config.get('keys', 'pubring')
        if not os.path.isfile(pubring):
            raise PubkeyError("%s: Pubring not found" % pubring)
        self.pubring = pubring

    def pub_construct(self, key):
        length = struct.unpack("<H", key[0:2])[0]
        pub = (Crypto.Util.number.bytes_to_long(key[2:130]),
               Crypto.Util.number.bytes_to_long(key[130:258]))
        rsaobj = RSA.construct(pub)
        assert rsaobj.size() == length - 1
        return rsaobj

    def pub_deconstruct(self, keyobj):
        # The key length is always 1024 bits
        mix = struct.pack('<H', 1024)
        assert len(mix) == 2
        # n should always be 128 Bytes so don't try to pad it.  This
        # would just trick the assertion.
        mix += Crypto.Util.number.long_to_bytes(keyobj.n)
        assert len(mix) == 2 + 128
        mix += Crypto.Util.number.long_to_bytes(keyobj.e, blocksize=128)
        assert len(mix) == 2 + 128 + 128
        return self.wrap(mix.encode("base64"), 40)
        
    def read_pubring(self, remname):
        """For a given remailer shortname, try and find an email address and a
        valid key.  If no valid key is found, return None instead of the key.
        """
        f = open(self.pubring, 'r')
        # Bool to indicate when an actual key is being read.  Set True by
        # "Begin Mix Key" cutmarks and False by "End Mix Key" cutmarks.
        inkey = False
        # This remains False until we get a valid header, then it is populated
        # with the remailer's email address.
        email = False
        # The variable 'gotkey' is set True once a key has been located and
        # validated.
        gotkey = False
        for line in f:
            # Worth checking for the space in the following condition to
            # prevent 'foo' matching 'foobar'.
            if line.startswith(remname + " "):
                header = line.rstrip().split(" ")
                # Standard headers are:-
                # header[0] Short Name
                # header[1] Email Address
                # header[2] KeyID
                # header[3] Mixmaster Version
                # header[4] Capstring
                if len(header) == 7:
                    # Mixmaster > v3.0 enable validation of key date validity.
                    # header[5] Valid From Date
                    # header[6] Expire Date
                    if timing.dateobj(header[5]) > timing.now():
                        # Key is not yet valid.
                        continue
                    if timing.dateobj(header[6]) < timing.now():
                        # Key has expired.
                        continue
                email = header[1]
                keyid = header[2]
                continue
            if not email:
                continue
            if not inkey and line.startswith("-----Begin Mix Key-----"):
                inkey = True
                line_count = 0
                b64key = ""
            elif inkey and line.startswith("-----End Mix Key-----"):
                key = b64key.decode("base64")
                if (len(key) == keylen and
                    keyid == MD5.new(data=key[2:258]).hexdigest() and
                    keyid == header[2]):
                    # We want this key please!
                    gotkey = True
                    break
            elif inkey:
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
                raise PubkeyError("Unexpected line in Pubring: %s" % line.rstrip())
        f.close()
        if not gotkey:
            raise PubkeyError("%s: No Public Key found" % remname)
        return email, keyid, key

config = Config.Config().config
if (__name__ == "__main__"):
    s = SecretKey()
    keyid, key = s.read_secring()
    keyobj = s.sec_construct(key)
    newkey = s.sec_deconstruct(keyobj)
    assert keyid == MD5.new(data=key[2:258]).hexdigest()

    #keyobj = s.pem_import(config.get('keys', 'seckey'))
    #s.mix_format(keyobj)
    p = PublicKey()
    email, keyid, key = p.read_pubring("banana")
    keyobj = p.pub_construct(key)
    newkey = p.pub_deconstruct(keyobj)
    keybin = newkey.decode("base64")
    assert keyid == MD5.new(data=key[2:258]).hexdigest()
