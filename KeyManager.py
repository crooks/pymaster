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
import logging
import Crypto.Random
import Crypto.Util.number
from Crypto.PublicKey import RSA
from Crypto.Hash import MD5
from Crypto.Cipher import DES3
import timing
from Config import config


class KeyUtils():
    def ishex(self, s):
        """Validate a string contains only Hex chars.
        """
        return not set(s.lower()) - set('0123456789abcdef')

    def wrap(self, s, n):
        """Take a string and wrap it to lines of length n.
        """
        s = ''.join(s.split("\n"))
        multiline = ""
        while len(s) > 0:
            multiline += s[:n] + "\n"
            s = s[n:]
        return multiline.rstrip()

    def date_prevalid(self, created):
        if type(created) == str:
            created = timing.dateobj(created)
        try:
            return created > timing.now()
        except ValueError:
            # If the date is corrupt, assume it's prevalid
            return True

    def date_expired(self, expires):
        if type(expires) == str:
            expires = timing.dateobj(expires)
        try:
            return expires < timing.now()
        except ValueError:
            # If the date is corrupt, assume it's expired
            return True

    def date_grace(self, expires):
        grace = timing.daydelta(expires, config.get('keys', 'validity_days'))
        return grace

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

    # Iterative Algorithm (xgcd)
    def iterative_egcd(self, a, b):
        x, y, u, v = 0, 1, 1, 0
        while a != 0:
            # use x//y for floor "floor division"
            q, r = b // a, b % a
            m, n = x - u * q, y - v * q
            b, a, x, y, u, v = a, r, u, v, m, n
        return b, x, y

    # Recursive Algorithm
    def recursive_egcd(self, a, b):
        """Returns a triple (g, x, y), such that ax + by = g = gcd(a,b).
           Assumes a, b >= 0, and that at least one of them is > 0.
           Bounds on output values: |x|, |y| <= max(a, b)."""
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = self.recursive_egcd(b % a, a)
            return (g, x - (b // a) * y, y)

    def modinv(self, a, m):
        g, x, y = self.iterative_egcd(a, m)
        if g != 1:
            return None
        else:
            return x % m


class Secring(KeyUtils):
    def __init__(self):
        self.secring = config.get('keys', 'secring')
        # State that we last did a Cache reload at some arbitrary date in the
        # past.
        self.last_cache = timing.dateobj('2000-01-01')
        # The cache will hold all the keys (as objects, keyed by keyid).
        self.cache = {}
        if not os.path.isfile(self.secring):
            # If the Secret Keyring doesn't exist, we certainly want to
            # generate a new keypair.
            log.info("Secret Keyring %s doesn't exist.  Generating new Key "
                     "pair.", self.secring)
            self.newkeys()
        self.read_secring()
        # self.cache is always defined because read_keyring initializes it.
        if len(self.cache) == 0:
            # We have no valid keys!  Better generate a new Secret/Public pair
            # and write them to the approprite files.  This should probably
            # only happen on initiation of a new remailer or after a very long
            # period of inactivity.  At all other times the expire/renew
            # process should take care of it.
            self.newkeys()
            self.read_secring()
        log.info("Initialized Secring. Path=%s, Keys=%s",
                 self.secring, len(self.cache))

    def __setitem__(self, keyid, keytup):
        self.cache[keyid] = keytup

    def __getitem__(self, keyid):
        if type(keyid) != str or len(keyid) != 32 or not self.ishex(keyid):
            return None
        if not keyid in self.cache:
            self.read_secring(ignore_date=False)
            if not keyid in self.cache:
                return None
        key, expires, grace = self.cache[keyid]
        if self.date_expired(expires):
            # Key has expired.  Check if we have another valid key and if not,
            # create a new keypair.
            if len(self.cache) == 1:
                self.newkeys()
            if self.date_expired(grace):
                # Key is beyond its expiry and grace.  Delete it from the
                # Cache, never again to be trusted.
                del self.cache[keyid]
                return None
        return key

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

    def newkeys(self):
        """Generate a new Secret/Public key and write them to the configured
        files.  In the case of the Secret Key, it's appended to Secring.  The
        Public Key overwrites the existing file.
        """

        log.debug("Generating new keypair")
        keyobj = RSA.generate(1024)
        #public = RSA.public(keyobj)
        secret, public = self.rsaobj2mix(keyobj)
        keyid = MD5.new(data=public[2:258]).hexdigest()
        log.info("Generated new Secret Key with Keyid: %s", keyid)
        iv = Crypto.Random.get_random_bytes(8)
        pwhash = MD5.new(data=config.get('general', 'passphrase')).digest()
        des = DES3.new(pwhash, DES3.MODE_CBC, IV=iv)
        secenc = des.encrypt(secret)
        today = timing.today()
        expire = timing.datestamp(timing.future(
                                 days=config.getint('keys', 'validity_days')))
        f = open(config.get('keys', 'secring'), 'a')
        f.write('-----Begin Mix Key-----\n')
        f.write('Created: %s\n' % today)
        f.write('Expires: %s\n' % expire)
        f.write('%s\n' % keyid)
        f.write('0\n')
        f.write('%s' % iv.encode('base64'))
        f.write('%s\n' % self.wrap(secenc.encode("base64"), 40))
        f.write('-----End Mix Key-----\n\n')
        f.close()
        log.debug("Secret Key written to %s",
                      config.get('keys', 'secring'))
        f = open(config.get('keys', 'pubkey'), 'w')
        f.write('%s ' % config.get('general', 'shortname'))
        f.write('%s ' % config.get('mail', 'address'))
        f.write('%s ' % keyid)
        f.write('2:%s ' % config.get('general', 'version'))
        if config.getboolean('general', 'middleman'):
            conf = "MC"
        else:
            conf = "C"
        f.write('%s ' % conf)
        f.write('%s %s\n\n' % (today, expire))
        f.write('-----Begin Mix Key-----\n')
        f.write('%s\n' % keyid)
        f.write('%s\n' % len(public))
        f.write('%s\n' % self.wrap(public.encode("base64"), 40))
        f.write('-----End Mix Key-----\n\n')
        f.close()
        log.debug("Public Key written to %s",
                      config.get('keys', 'pubkey'))

    def generate(self, keysize=1024):
        k = RSA.generate(keysize)
        public = k.publickey()
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

    def rsaobj2mix(self, keyobj, secret=True):
        # Calculate some RSA key components.
        keyobj.dmp1 = self.modinv(keyobj.e, keyobj.p - 1)
        keyobj.dmq1 = self.modinv(keyobj.e, keyobj.q - 1)
        keyobj.iqmp = self.modinv(keyobj.q, keyobj.p)
        # n should always be 128 Bytes so don't try to pad it.  This
        # would just trick the assertion.
        secret = struct.pack('<H', 1024)
        secret += Crypto.Util.number.long_to_bytes(keyobj.n)
        secret += Crypto.Util.number.long_to_bytes(keyobj.e, blocksize=128)
        # Now we have the modulus and the exponent, take a note of them for
        # the Public Key.
        public = secret
        assert len(public) == 258
        secret += Crypto.Util.number.long_to_bytes(keyobj.d)
        if keyobj.p >= keyobj.q:
            secret += Crypto.Util.number.long_to_bytes(keyobj.p)
            secret += Crypto.Util.number.long_to_bytes(keyobj.q)
        else:
            secret += Crypto.Util.number.long_to_bytes(keyobj.q)
            secret += Crypto.Util.number.long_to_bytes(keyobj.p)
        secret += Crypto.Util.number.long_to_bytes(keyobj.dmp1)
        secret += Crypto.Util.number.long_to_bytes(keyobj.dmq1)
        secret += Crypto.Util.number.long_to_bytes(keyobj.iqmp)
        assert len(secret) == 706
        secret += "\x00" * (712 - len(secret))
        return secret, public

    def read_secring(self, ignore_date=True):
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

        if not ignore_date and timing.last_midnight() <= self.last_cache:
            log.debug("Not repopulating Secret Key cache.  This task is only "
                      "performed, at most, once per day.")
            return 0
        log.debug("Reading Secring to cache Secret Keys.")
        f = open(self.secring)
        inkey = False
        for line in f:
            if line.startswith("-----Begin Mix Key-----"):
                if inkey:
                    log.warn("Got an unexpected Begin Mix Key cutmark "
                             "when already within a Keyblock.  This is "
                             "ambiguous so we'll do the safe thing and "
                             "look for another key.  Intervention is "
                             "required to correct this.")
                    inkey = False
                else:
                    key = ""
                    lcount = 0
                    inkey = True
                    continue
            if not inkey:
                continue
            lcount += 1
            if lcount == 1 and line.startswith("Created:"):
                created = timing.dateobj(line.split(": ")[1].rstrip())
            elif lcount == 2 and line.startswith("Expires:"):
                expires = timing.dateobj(line.split(": ")[1].rstrip())
                if (self.date_prevalid(created) or
                    self.date_expired(expires)):
                    # Ignore this key, it's not valid at this time.
                    inkey = False
            elif lcount == 3 and len(line) == 33:
                keyid = line.rstrip()
            elif lcount == 4:
                # Ignore the zero.  (Why's it there anyway!)
                continue
            elif lcount == 5:
                iv = line.rstrip().decode("base64")
            elif line.startswith("-----End Mix Key-----"):
                inkey = False
                plainkey = self.decrypt(key.decode("base64"), iv)
                if len(plainkey) != 712:
                    log.warn("%s: Decrypted key is not 712 Bytes!",
                                 len(plainkey))
                elif keyid == MD5.new(data=plainkey[2:258]).hexdigest():
                    keyobj = self.sec_construct(plainkey)
                    log.info("Cached valid secret key: %s" % keyid)
                    # The cache contains three objects: The key, the expiration
                    # date of the key and the grace period beyond expiration.
                    self.cache[keyid] = (keyobj, expires,
                                         self.date_grace(expires))
                else:
                    log.warn("Read a Secret key but the stated KeyID (%s)"
                             "doesn't match the key digest.  The only "
                             "safe action is to ignore this key.  "
                             "Intervention is required to resolve this.",
                             keyid)
                continue
            else:
                key += line
        # This timestamp is used to ensure we don't repeatedly attempt to
        # cache a key that doesn't exist.
        self.last_cache = timing.last_midnight()
        log.debug("Cache written on %s.  Cache will not be rewritten today "
                  "unless a restart occurs.",
                  timing.datestamp(self.last_cache))
        f.close()

    def decrypt(self, keybin, iv):
        # Hash a textual password and then use that hash, along with the
        # extracted IV, as the key for 3DES decryption.
        password = config.get('general', 'passphrase')
        pwhash = MD5.new(data=password).digest()
        des = DES3.new(pwhash, DES3.MODE_CBC, IV=iv)
        decrypted_key = des.decrypt(keybin)
        # The decrypted key should always be 712 Bytes
        return decrypted_key


class PubringError(Exception):
    pass


class Pubring(KeyUtils):
    def __init__(self):
        keyfile = config.get('keys', 'pubring')
        if not os.path.isfile(keyfile):
            raise PubringError("%s: Pubring not found" % pubring)
        self.keyfile = keyfile
        self.read_pubring()
        log.info("Initialized Pubring. Path=%s, Keys=%s",
                 keyfile, len(self.cache))

    def __getitem__(self, name):
        # header[0] Shortname
        # header[1] Email Address
        # header[2] KeyID
        # header[3] RSA Key Object
        # header[4] Mixmaster Version
        # header[5] Capstring
        if name in self.snindex:
            # Check if the requested name is a shortname.  If it is, change
            # the request to the corresponding email address.
            name = self.snindex[name]
        if not name in self.cache:
            print "Name not in cache"
            # If the requested Public Key isn't in the Cache, retry reading it
            # from the pubring.mix file.
            self.recache()
            if not name in self.cache:
                # Give up now, the requested key doesn't exist in this
                # Pubring.
                raise PubringError("%s: Public Key not found" % name)
        if ('validto' in self.cache[name] and
            self.date_expired(self.cache[name]['validto'])):
            # This is a later style Mixmaster key so we can try to validate
            # the dates on it.
            log.info("Key for %s has expired.  Deleting it from the "
                     "cache.", self.cache[name]['shortname'])
            # Public Key has expired.
            del self.cache[name]
            return None
        # Only return the first five elements.  Nothing cares about the dates
        # after validation has happened.
        return self.cache[name]

    def get_addresses(self):
        return self.cache.keys()

    def get_names(self):
        return self.snindex.keys()

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

    def header_validate(self, remailer):
        """Perform crude validation that a header line complies with what's
           expected in a pubring.mix file.
        """
        valid = True
        if len(remailer['shortname']) > 12:
            valid = False
        if len(remailer['email']) < 3 or len(remailer['email']) > 80:
            valid = False
        if not '@' in remailer['email']:
            valid = False
        if len(remailer['keyid']) != 32:
            valid = False
        if not self.ishex(remailer['keyid']):
            valid = False
        if ('validfrom' in remailer and
            self.date_prevalid(remailer['validfrom'])):
            # Mixmaster > v3.0 enable validation of key date validity.
                valid = False
        if ('validto' in remailer and
            self.date_expired(remailer['validto'])):
                valid = False
        return valid

    def recache(self):
        # If the file has been modified since the last read, it's worth
        # reading it again.
        if os.path.getmtime(self.keyfile) > self.mtime:
            log.debug("%s modified. Recreating rules.", self.keyfile)
            self.read_pubring()
        else:
            log.debug("%s: Request to recache ignored.  File has not been "
                      "modified since last cache.", self.keyfile)

    def read_pubring(self):
        """Read the Public Keyring file and cache the results in a dictionary,
           keyed by email address.  In addition, create an index of shortnames
           to email addresses.
        """
        # The cache is keyed by remailer email address and contains all the
        # related data in a list.
        cache = {}
        # The index provides a means for items to be extracted by shortname
        # instead of address.  It might be removed later but for now, other
        # elements of the remailer code depend on that ability.
        snindex = {}
        # Headers is a list of the remailer header lines found in the Pubring.
        # This is used to list known remailers in remailer-conf replies.
        headers = []
        f = open(self.keyfile, 'r')
        # Bool to indicate when an actual key is being read.  Set True by
        # "Begin Mix Key" cutmarks and False by "End Mix Key" cutmarks.
        inkey = False
        # This remains False until we get a valid header, then it is populated
        # with the remailer's email address.
        gothead = False
        for line in f:
            line = line.rstrip()
            if not gothead and not inkey:
                # The components of a pubkey header are delimited by a
                # single space.
                header = line.split(" ")
                if len(header) == 5 or len(header) == 7:
                    # A valid header will always have 5 or 7 elements.
                    # Standard headers are:-
                    # header[0] Short Name
                    # header[1] Email Address
                    # header[2] KeyID
                    # header[3] Mixmaster Version
                    # header[4] Capstring
                    remailer = {'shortname': header[0],
                                'email':     header[1],
                                'keyid':     header[2],
                                'version':   header[3],
                                'capstring': header[4]}
                    if len(header) == 7:
                        remailer['validfrom'] = header[5]
                        remailer['validto'] = header[6]
                    gothead = self.header_validate(remailer)
                    if gothead:
                        headline = line
            elif (gothead and not inkey and
                line.startswith("-----Begin Mix Key-----")):
                inkey = True
                line_count = 0
                b64key = ""
            elif (gothead and inkey and
                  line.startswith("-----End Mix Key-----")):
                key = b64key.decode("base64")
                if (len(key) == keylen and
                    keyid == MD5.new(data=key[2:258]).hexdigest() and
                    keyid == header[2]):
                    # We want this key please!
                    headers.append(headline)
                    # The key object itself is inserted as the fourth element
                    # in the list.  No good reason, other than it needs to be
                    # inserted at some fixed point and the total length is
                    # varible, depending on whether dates are present.
                    remailer['keyobj'] = self.pub_construct(key)
                    # Here we key the cache by remailer email address.
                    cache[remailer['email']] = remailer
                    # Populate the shortname index.
                    snindex[remailer['shortname']] = remailer['email']
                    gothead = False
                    inkey = False
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
                raise PubringError("Unexpected line in Pubring: %s"
                                   % line.rstrip())
        f.close()
        self.cache = cache
        self.snindex = snindex
        self.headers = headers
        # Reset the modified file time
        self.mtime = os.path.getmtime(self.keyfile)


log = logging.getLogger("Pymaster.%s" % __name__)
if (__name__ == "__main__"):
    log = logging.getLogger("Pymaster")
    log.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    log.addHandler(handler)
    s = Secring()
    p = Pubring()
    remailer = p['dizum']
    print remailer
    print p.get_addresses()
    print p.get_names()
    #print p.headers
    #if remailer is not None:
    #    print remailer[0], remailer[1]
    #    print s[remailer[1]]
