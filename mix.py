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


class Body():
    """ Length                         [       4 bytes]
        Number of destination fields   [        1 byte]
        Destination fields             [ 80 bytes each]
        Number of header line fields   [        1 byte]
        Header lines fields            [ 80 bytes each]
        User data section              [ up to ~2.5 MB]
    """

    def body_pack(self, msg, dests, headers):
        payload = struct.pack("B", len(dests))
        for dest in dests:
            payload += struct.pack("80s", dest)
        payload += struct.pack("B", len(headers))
        for header in headers:
            payload += struct.pack("80s", header)
        payload += msg
        payload = struct.pack("<I", len(payload)) + payload
        return pad(10240, payload)

    def body_unpack(self, body):
        sbyte = 0
        ebyte = 5
        length, dfields = struct.unpack('<IB', body[sbyte:ebyte])
        dests = "80s" * dfields
        sbyte = ebyte
        ebyte = sbyte + (80 * dfields)
        destlist = struct.unpack(dests, body[sbyte:ebyte])
        sbyte = ebyte
        ebyte = sbyte + 1
        if destlist[0].startswith("null:"):
            #print "Dummy Message"
            return None, None, None
        hfields = struct.unpack('B', body[sbyte])[0]
        heads = "80s" * hfields
        sbyte = ebyte
        ebyte = sbyte + 80 * hfields
        headlist = struct.unpack(heads, body[sbyte:ebyte])
        sbyte = ebyte
        # The length of the message is prepended by the 4 Byte length,
        # hence why we need to add 4 to ebyte.
        ebyte = length + 4
        return destlist, headlist, body[sbyte:length + 4]


class HeaderUnpack():
    def __init__(self):
        self.sk = KeyManager.SecretKey()
        self.sk.read_secring()
        #seckey = sk.pem_import(config.get('keys', 'seckey'))
        #self.pkcs1 = PKCS1_v1_5.new(seckey)

    def unpack(self, first_header_bytes):
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
         enc) = struct.unpack('@16sB128s8s328s', first_header_bytes[0:481])
        # Use the session key to decrypt the 3DES Symmetric key
        seckey = self.sk[keyid.encode("hex")]
        if seckey is None:
            raise ValidationError("Secret Key not found")
        pkcs1 = PKCS1_v1_5.new(seckey)
        deskey = pkcs1.decrypt(sesskey, "Failed")
        if len(deskey) != 24:
            raise ValidationError("Session key returned incorrect length "
                                  "3DES key")
        if not len(sesskey) == datalen:
            raise ValidationError("Incorrect session key size")

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

        Regardless of the Packet Type, this function will always return a list
        of 5 elements.  Those being, ID, 3DESkey, TypeID, Packet_info and
        Timestamp.
        The Message Digest is only used for validation within the function.
        The Packet_Info is a flexible list of elements depending on the
        TypeID.
        """
        if len(decrypted) != 328:
            raise ValidationError("Incorrect number of Bytes decrypted")
        # Unpack the 328 decrypted bytes into their component parts
        (packet_id,
         deskey,
         packet_type) = list(struct.unpack("@16s24sB", decrypted[0:41]))
        if packet_type == 0:
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
            # Checksum includes everything up to the Message Digest.
            # Don't forget this needs to include the 7 Byte Timestamp!
            checksum = MD5.new(data=decrypted[0:280]).digest()
            #print "Next Hop: %s" % addy
        elif packet_type == 1:
            """Packet type 1 (final hop):
               Message ID                     [ 16 bytes]
               Initialization vector          [  8 bytes]
            """
            (message_id, iv, timestamp,
             msgdigest) = struct.unpack('@16s8s7s16s', decrypted[41:88])
            packet_info = []
            packet_info.append(message_id)
            packet_info.append(iv)
            checksum = MD5.new(data=decrypted[0:72]).digest()
        elif packet_type == 2:
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
            checksum = MD5.new(data=decrypted[0:74]).digest()
        else:
            raise ValidationError("Unknown Packet type")
        if checksum != msgdigest:
            raise ValidationError("Encrypted header failed checksum")
        self.packet_type = packet_type
        self.packet_info = packet_info


class HeaderPack():
    def pack(self, keyid):
        test_data = "SteveCrook" + ("x" * 318)
        assert len(test_data) == 328
        assert len(keyid) == 16
        header = keyid
        deskey = des3_key()
        # RSA Encrypt deskey and assert length = 128
        iv = des3_iv()
        enc = des3_encrypt(test_data, deskey, iv)
        return header


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

test_message = """FCj37A0ej5BsjANwZGQg94CU60GoXBjIEXqXMY13
oPxgrEn6Jzw+h9PvO2k/lZxA7FWhjfVJEka03UfJ
7td/6IBfKGx42GpYde5mIpBFsTIvaxgJIeUXJ4Fl
JrAM97MLiP0s4EHUxaDB0Rtw8wVckvuGXsMQMmye
SYeUD8EJQODk1NCdU4eUdvVnKnrQgavpSc9gUw5J
UzuThEjPbKDBFXeVB5GR3ZKCy+Cx5/VGF8yI3qqN
6Vky0EsxvPjDq2gymlhTcUbCeLlrs8gDqVp9Itie
75e8gISmv6xcy6JWEaRLnYXBtSlUePAYZbN4WMYH
eAAjvqCVNqrThV4yfs9gIN5Ea+VVc1CVn3jO9kLC
88C/3tGQHzvf+BXhJR12v+RAwkdmCZMKMeQqvYcM
YlQE4N1rlTh5iN6xghULe+oi9XE51o1P2iA+2XOz
aPfooMl6v33DVwwskBwyvFy/OG7/+vLVjW6jzTO3
ROSTJX85yUTg3Lpam+G1sXXmyGacK5/1uISF2Qz9
vXIXRQD6X3bv46WlR4x00CbmCZPqxg9oFdEwvhla
IOtWRmxSKhyndemPfGHe2Aamkd1Jj0KZB6Z3HMR9
7Ydng+eW4jjk7yM3yYE6OU05tcE+O6z0xAw6eoJY
S5lNnSZksBan4NAs5sH8xQ+6KeH7fLT4jrQZq5vj
Qt7xsHzyZrHVJtcwebe8LjNNAQZ0by3g9hJomL5V
J9mvTRTAlPhWhAakNJUUjkdMCj4InPqeDQhYK5tQ
hU6gq6+lP1mHFi4DQDENtvdyXBvaQrdXdaeZHAqP
PABB8zdzoS8/BeQ986Fp9k/9Orfe6iHhalVNTx8o
DwJKOj2MABpHzrMXyCBZAc9DSB7ajq63ORyVNUNw
6N+p2JwqutmxCwyXP6BTPz+AJ4HgVb/26DlVWPub
4JR9y98ZX+A848x82+kLJE9bjVdOlDkyBze/BOWY
pDNnoo8++gwcsdM2AHngv3EME5EdQYmbArbCEfXN
aW4jRYIdUZUzP1mTPVw5b2WzoJS5hOBTSgP8V8IG
a/jHJrTMlIgu+lu3BtZS52c6FpRICArGK+dhLlV5
yWKH4W940rak1438/vRaArKWKfdHEPEt8geMut1N
tXwPIdLk1ybQyFBtW5rQH/0cHMaiWM8PqJ3ZvNuW
tdGcrcjHivgsLbD9y5njQm+M1PBcPJ+FyKx37dAb
97pFWmxReR5bksiHqeFwCRU1QMIhJ8sQpBTEyLvz
rl8NUr2kUenCErSJ4BNEQFRiD1wHt32bk5iuBFJ9
ICr/7aAz5iRGkf0Hr7wETDfLEUr3qT5GopaCt5gO
TtCXQhULnp3OGANIDeHEL57Imhs2aohy/6SCE/Ig
sXh9dR1HsnOkl3CP4iCpc9io6MGeHqvVUDUAeRKg
vaZrf6VQ/f2WILfn9Hx/onyUfAN+zrePyhQtnft+
QVXAhk8t7Et7ozLTO9Uh2Pyd7MiOftvWxa1v5Kxh
iY8148iXEhuoNWuqPHc2ZR6uTRt3O0T14+gDGRx6
hwVC1TVjtlqy8Q5lYQ8llpj8NmwAGBKi0ZASS3UV
ZJ4yj7bFb6lla7uTsnWCb3OmEnq+rZ4nZKuVLP6k
MUhodkq1DuZiBQE9M/KkhiQ/4FurHtKoUem3zGWL
VHD05m5yMAJtZNABb6a2lOjUshCVEi5DxOKihgQs
1ZdBoS3AFw8SIYHr3hmZ3l/4HHfwbYB/vBCScMCr
rMcrZCgkOpx6wf0M7bXQDHu/XOKcHYW+8RADJj2D
pCNvGAbia0GkQnwLpKU1R25AT09oiCrLAgjbsX7C
cuwE2MxXhY9UmnW2ehcsf7fz6TJA8lP4CXluFXUt
E0zn4sIy3Ubz4BJhH9DH/cMEeclv0c/B9GLwo+o4
Nl0QbwrTp6WdIPFfZA2M2N+u6NoFkTMVeuRN5Lg4
o/wBPHgBn773fr3+vIV/IqDBNnAUULJ9v4Pxbc8N
e7T81ZUFJcevNRmf20/rR/HvGQ39R1z7x2rcQxGn
AmZjfgIw8rpo/J13UFTl9ICFl+DktSh6sYVRyUq1
hf7AOaAePwlPVPvtkEhcApo4+EkMhHbt+0kdTSrl
u6LJzYJH/WXCOFQXEVT0PjUunWhYnpPkLvT1pnC4
m34PjsMbvTEQeq9ORTGn2nEvDVZyKqRPxHOOtAQU
T9SZYAgxkLEZnVfoqla9Kk5myn+7fZWcYPqhHtlM
ONu7pRqpU6nyd9Jk7cVrBBDSjomokNSG+m4Vf1Zg
uSY55FEXrResW4a/cTlmRlvhvr8y8ZjaMiDs2tqc
b3Q5PpMBLmtRFAbgHSk2Be+hue0CMF+yF8B1zMur
0gX23vh0VXIDO0l0HHBnMbVBWrzBYUHyPdaS2QtT
M9yjIE5KWgoVpLzSNOOBJnsmz4soPz7toP22GnNC
mlnVTFOyURpBLH7InYat/Bf/gVfR+lwGorXwSvJp
iGRLG3bYWsRZLsbYJ1fJTEB6YBUHXeU2K8bGxHC5
qsf53nNnjAt4lfcs08nvqubRN67dmP6BJy6KitUq
owHLfwueRgOkZwVqahIP3IoeCrayaYWEyOQFPYTh
vRjmU9urF5D9xq1tY90vGSC9lPY4zNfaFJnFmAmu
Ha1YKGY/HTNbdohn2R3h1hiDK8p/+HNNdXIJTIL4
M3kWDyi4mEVjlAOxOsW5AWMaFPhdQZ8FTcIUCuQp
b+HSc4AsN9YPqj/PHAbtmpTDfr5EP8AwxQCs8U25
DeqzILba2C3UQxJ8IzWbgzo8CMCQgd52YsnJcrvo
pJRTIRPxTaDMlT7tjWqXGAYn8UHjvcBCdASy/YaW
++w1ABUptaImb4Cdtg6EI+LXQ3qvrmQDoALSfnTp
sGttJvTWebj07OkdBk1uHL7t82pX2m2WTDsVU9PN
ErOHa26Ofu0A1tpS4MrvlJFTOx2rsxal1vzq3vXt
+11na2wQkNp5P1/14cvVy+1lH1JqkEiFsKrH8T2d
LOSsDO+g48eLA8VEKsNapDaIZKKVYGM6eR1zPucs
FSRz77nfxFVmf+Cxu3y4IXUg2J3aYUjVZ6BVM9WE
kKaHvSPiecykdsn9vWfaz12XCNQuddwiRShkhTMt
msR76PDYAeY2BSCO9kDjeg9BnguYc5cbXzMjdisa
o5jPL8TSBisGRSSrIarLml/SyOKtqH0Vi2IUqg+e
v9WTFIS4qUk6NKTWe79zigSpgrQcHlX3ZqdPNNy1
6pK/meklZZ78rKAH6iwAUs/Y+iUYhQfVw2uyYSu/
as1daPZkgmx+zL2fBBOb871CnEGGzXdtbLbKXor5
Gvk498GBAoKc4DG/nyms8z1YKkaZ3Ep4lFi/OtRK
e+CkiRf2vxBOzWxCVcQQYJxoU33F+q4mvcrGyQjN
1SZXOtdcbQAO/qwnXfn91sxGHjEfIFJSpnCYfsqO
8cufebGfLD0l4UZySEgy+gCOGXMkk6gJrX+3kPtb
t0arPXYi3s6WL50S++nkqB9Krcxe05CjnINvTN6A
RqoQhZ9VI+xYtPHWsLIspuvAdAd6z1X6sGF7YyfA
ErlyFUg3P/WBNSmyQqHJl02CrlEmbA3YcLmo2biH
40SEfFeixfv+QwAFycRyoFnfqrdxHB8YIFS8bjpv
B7vkmCHavL9V1wdhqn1DVQIIaYJdiCDBpn4EreXG
Lf7qEEwaBt0d21J93LPevOzrPwmUzez57hgIk4He
ljjygRnPzZdFfeUN/OyZz1+KY3L4UMdFUYgeZoKd
CUzSJ0UKwIi0LcTRoe1NDm4ZCBz8iw+QyxdNwLJH
k/g4hoSk4hBRDGY91JZnrzJYjNGf1870dup2I/yF
HYX0Mb0qVoC3mhOkwEwIZuxxqH1GBsCUjZmuIF6t
paHAcWVlT2CttjHpkGh9Kn0CZhre25PN3ap5l5Mw
JH688Pr8WnXNNrr7Z/kpWe2o+lrBLu5pUDS6aWpa
6v4MrsfJFDF/GMlcueuIAsobUKZMBTucygo9gr/V
fwufzirVVlEsedYq4pYO/gLHPmlmXN9p8WnMVRS1
JpCQjQDNEPXOMYAZev88AsMJBi4AG/nK87sSezjm
2uAkzUB6QJUFcbxFNNMTv0p/pHLApAu5OdNnPtjX
jSEI0HDX+KScBGUwronl8iOpkY2l/xp3gC5sO4gw
SB2OYRrkQoa8vVFbDrLBMmNBe8o4DqQWzqvTdEZN
Tth5JzbnqiRT7m9I0fDGHlLyRq6v6Hb8FLWqdOTO
L/pBVbbgwSxZ579Bf4miaf39O6y2JQNv2hDNqEIg
YKHEDtqJEoAD0iiv/4/BiBScEzD3z3cD7CnILc6k
lwRhLYtSbDEoUsU9ZtNjJu03ZAHDL9zk922tKm7A
FbiR/YOY/JjhSqwoBmYYm4gRkaTH6xCj+VMwTgUL
dXdxe7VlYfp8zsoRc3iGkfpXDUZd3cLW+lh0/kX+
9V9kePA7YpfG4I4OgzkWrVXx8AjHEYwUrsAzocl/
V/bJFNiY67/VD7m9aTc+KE/+VDKlwHPLeyvJrDmS
7y0Kj8t3W4s2OrQMmMGfEBfd8E8qpyao3a2Kcr1p
dX73pt7hi1rhJOPdPTal6bWSAxCdkvqHUYujMUQz
/eRu2rfZA2X2j9SQR9evg9e8g9NwF32XNmPR8XyG
BXhigvYeiscqwmCvDfnV+gINLs/t56i6y7j1vbYN
ZPCGvd0swZJ6FBcjWDZDKiB1/wi6Yo4wnTCjflTh
b0kLIQJqM4GEoBqSyr2qCIwywFXosEYZWal1P1qR
pmiWRIyTKLubePnmwOQ5HPfujeaDjg/wrpY1mxuH
cFro/jbZI8rcYSv4H+fnCt0jexsgt1LNzapOLdi/
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
iK+2hTLpAjJTcy+Psvs0EOdpxC6bs7x1PMLJhumr
Yer3Z8xVZcNRt8+RSb9UzLDaXnJehKwlHzWcyNAY
Wbnwto5a4+Xo0151ER3aD/PLWZM3KSrnR7ZV+Zsh
Dt1KDJ3bWKe8AArdluFPDlGBuHxCZGbuLPUbNYj+
NJ3Y+sdhpksmNrwcipEMZpHZgr+sWq/G4hdTurTH
ns5eWjub42b+EdjLN4yap+gjWUkSgPoYJWDn/mjd
HJaNZ6f3ZQ9M8DO/CefY/U4rfHX3QnrZx1uF4Qom
xMBnghb3R9i4FScxCTS5yCqFMue7egvKhNOcSF+n
LMXzJmWDRSDCmgnYykIlySCfyyeN6qWJONd8k6S0
sY5OfU5vqNdqLdVF92uxrI1snkcjZMD8cNQA32Xv
IdMIcEyOV7Xks3fwmTHVcQfrPNiYeuJFv58rfOwL
Jr5p4G3ZzahBqxLxMasOUM4M6yf/szkYsro4uSof
fk7niKPzxaoxWC0UXd79plXzSgm5tZ+iU9ENngdL
cRjK8ShCIuT6rZivVjXfGzhMJ3u0wZJ/RG3fgOaL
OMvpiYR4dxfUeYTYq/k+MPrydQuOImmpKOcQXirg
YWD4tWM4VLbvlLWY16XwsYzJPahCKylhDsy9UDWK
ZY6Oq9/RAieZPBk2JtHYhmWAo7RuICTBSOTGZRao
LdpkXVRO/5JfZpDp6HV0kpTm6nMvD5HUJR6LQoJ/
wQMxWbaRKv060X6h/c9lenQSLmNO5AqP+GdOIihM
d5T+rJYujLHcmhNrG1O/vS/Bk760MCraChy9GP7N
/T/rxqVNClrErXwOQNS5K1nPW0xi0T/jpVIxCB7I
NTgFMT4egteuq4rcXqIwrUqVaTQAzSQeEo2hxw5p
dFIyO6NLCjzWdsRzFFX1ajWjf0KMD3f7D5cTM5XW
8fWhLNDBsB8VAwhfwHgewXjNraHSnSPjhuwfqGyu
IVUo822fX7+1Okv/YAiLmd4vyOlUkkXlRTrdZyAg
Ae45Of7jyH/ZOfy/GTGbxLf78uLHcPy1xuA/+GKZ
f0Dtv9uv30l6ZwmFLZIS0jaKkc7pDZ1JA+7EMIql
0y+n6om+2+QMLbrWM/nHzxrAghkQoJFZ+awuaav+
GCStcCqQrnNLCBZJ1twEwszmSkLMOpP31s15qnlX
bA0Vwis/JGpHLCFO8u/YqTh11fZFjjVgmtd5d0JE
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
my9nDrtE5AK48WXXdvNVRvk1+phD+I09WJorlk+3
gWH7L0PwDSnu2+AXfdGYnx1SoJLIhLpxK+eAvnfB
DIgQG6/Lbl5SM1DC6nW4pYiNIR5Uj27Wln9ibOjt
wdpTg9mMpSU+vGac9olbqHZ6JcugDYgQacyqyWHA
i/MGKdl96VfqiitIStp86IvZFeMZle9yeWeTcnGJ
5wCAgy0amE4YF6PnuFV5KJWgXRVvI3Y5m/SFiJ9F
aHSe+9ndKewzuXsBbrP2FVk7p0Nj2vIDBQ3hUy3w
JT2XKMA1pZ+qO/+6zsuRzOgeNx3f1oBu9KqXR1m1
86sh21K4ZRLw8C8OFBp7JtiJmeBiQzJUv9sYNt4Q
lIttLeOo3OcoIkZOowMK0/tStp//wdMG3ca/n40i
CswpPwtcfHM7iMxWFGKeVBWxTe2kO6+YKdkK911G
lEntCcjCsdJ+qh2deD9bW81kNGCPKhyLnpfnbisz
yh6Vrm4NGPAusVUa/Mbdd+M8UvKCpIT7tlGG1m86
muI4aMru3lTh+sjkZEze2n0HjcdaWpYEaanemkA7
yvYsZdpkq3zZMq6ifx7/SYHIzqk8qiQUnMi1NuG6
8WKnr0MhXJAud8nCOEYXmU9+s3JVAyfcQok0UN9W
7heEbE4RZeXuEHd8pMZLeeXjQwAejS7iN4oCGGGc
CfX4RT6+udxyZxqmcGhlg7IMNKPIqvIRP7Xk7Nu4
QCzANO+xs9QS34uuIIMzEwlGp43hohsjECiAK9jr
WqTRKJ53wTPEUjh/N+K9fFr+VoKw1eJjyy/O4XkH
U/McX4aUvcB04hDCSVAFLSAkL8KMsoNdA3zXetcl
D4VUQq6hTQo7J7EdJV8HG4XY262Vr9XAGL2WrqZS
2G23DhVJIg3ZILPhza9QzXZrLolaChOMIvS6obDM
hxLwN/PC7ag40fgrQJ1iRDtaBKg+EEXkuI2wX291
HEXiE3OHcfWLQnDjnKGAor2Pqz1FUmHOQdF/4qq0
ruCpOQjW4lFP8WadJTXeJj0XF1gXRN0wFq5xaxGE
irP7LkdMw5WnHjK2lq7AyMrcL9UYk//cvt+6wjUu
CKoNh/mypLy3Ah938+bz2GeXZczYckLqpp5Jw2mT
nNYv1hZSYqdXXv5qkfZpupCUYJcwB+yp8SOXNWE5
nrSyelSsaWoE4CMhaRk4n4UGPfyz8NQ+wY6X8uko
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
uo4Rq0mzSWFL1BbdORd+ErwzpQuPIrN1pvGU/2Hj
zpph3G8pmMK2XgRDGSvTuG4tKYiRITvhNzv9If0B
qXbLEqveN+VoqCxieugzi/xFHOs/CSw4cUd6jTu1
0YktNujbRvuJB8X2wpxYmWyPBiaItFhilXzXPVit
2YX0h9XdqaRw5tlTkN2XS994wLKcnkTXLMX7yTMk
0llRvrgmtIKivZQiLmAFKpEPxUdnLeHIu1KZwWl7
FBXfxRbyEZkD/IFQKpAkQrIumYtwNkcR74tdSIi7
B2exmQOj7yAEmMUQaAY7AVlSHXNpQZ8BIq70EcCl
ZClh0b+J9Td9M+acrJ351e73Ih2puemORxI2mKIM
GFCHcfvANkHrJARgI7159CJpExMx9khJxnDI8vpa
WReTjiaYh9AgrfjOsIQXlgLL7VGBi+ceXL3BTQQM
/abjs3Kdauvq+Lju9e/3ipDYajy3EPBpe50UO9Y1
67UrzbsjY5MYlMiCrNZ9nlBaTZNo2lTt7RqGOfMC
tiNh86o4UTHY4gQvWrtDRCSxlLsMUSRLfzg7XbEJ
8b8IIY/ECHzVVUSUIIgQiFKa2ng56y2Ixnj0A5mj
9m8+q2AFPJXZM9tqjQrcHzJzFbZ1r7Ih+Je9yudG
KC2fRPpbqPkYTz2NcFJZmJh+Cc7GQCk8+B5nn8XK
OKkBcy232mN9iJMTwiJEq251wrBjcq51x515Wga0
m6FvVIM4igZC1QsCj/kZH4/tZEt7vldk4SlbNCvP
OFAREVhzwiZzZZDPyy+XxyMkq2EJcKulBt13Shom
eSu1v0EIkSaEIwZeDYN8PFLDzeD/Koe0HE6goPpq
SCY/mu/Zj5+fyY+h48+18myaZGSRxnh8fPnaFo2k
xh8/1YYK4jQVLAfProbdtARusmNWiDOLppqhnT4c
aisZyh/ZWC842ENjdQKhOJ3xmBgGFQtB7AF8O0dO
uPBZaWM7QlVbSFxo2mTaud5SUVGJxc1yBtoS24D6
QxrVMrJyNRFPaxBhdzGh1U1Ar6DoxHg6bRfza8m4
1uifSAd380zyxtGXiRE0MdlELwDsYqjdirwleYdQ
RAe7UZNRcxTCAPGZhZMLe8/FIA3ELpyWu90lzHsT
pwNMZ2FDz798a0OUb4+QMj7xugdLCtpq1cO+KJPS
WIuGhp1mMtXYYCdXz5m0OahWcgkzVCYxyoQNImsg
5uD3FmRwBHTsGaG5YoLf1uLE7bKMvOdutwEfiRzf
Og4X8x+BwbqSp6G/ztFPZ5cLHXxTtnzfq5OPRxPr
j3RRvkag/wcaWLp2tqDQXwFpNbNGLD/AcyQWnXcS
ZaGZnAs9xQ8VT6Yh/2Bfi2t9VlSFs7/SndnonZjO
av836Gku2fG2OW4YWSJfqXJfINE8khJ5MHq7+MfN
vjP3pmvhuFU61F+XXUo/VFku8Ok2iy5jSjHdE4sV
3VjOYksXHlK5fsia5dFaFLyVUhHgv4mkpGXiiS+Q
+r2CNydA4h7H0PL2H8Nsjt47VDoaMRZAvDdX/bKM
8RUyNqaOefSzPgZl9uwl/PgnN0AU43P2dkZFo0Ag
jjlGIMVIwNqzKjmLDkBxODo1By2NIKVNOx0ZofDP
18UJWvaiPBKY1tNrrOiEaD6n6vHz4qp9bCFtlVyO
XQU2I4pCixo0IU92ncQZKwSM7MWFz1TuAzzOaak9
kn22FWmkNnFnFbon7MM6sN2uv1VNp+itSlW0GRlq
9MBPOJS1Tu4Ts1GifEoOSDl1MWW4ZT9LuBSKg2ju
atA03tZcNaDO7RtYS3CLuhd+OhLM6KdVCh6Fn3NR
8yyA8irWPvJd7ZHUlAsfpBTF3RCBdHW4U7Os+2oo
EQP9NkPKT1fp+Wk4254V/IARDBrYQuugc6bhAZH2
h34TmVjziVHzD6AVLyJNSIQEMinr4gyDXh2FVRFy
x5T9Ocf29a8LXMezrZC0FI6VgqrhZg4CB5zxvZKx
kCg1Is09c6MH9H56o0iBmM8wn+kmPbryPet74XKN
VWC7ybi7HsVHPcOouVycG8Jpo3KCgfQOf4b4i+or
5QQ7leMJi054YOBjcqadk68egGXNgIhnfO1dV+Fd
0KhizjO2ZjNY0JAPh9sD6+ndAMUCcaTtQSVeq+15
UugoJzzjNgnvDTwcCKKXKfdpEqVPd5VtwMyZekHK
RZ9YA0yKJWiZQ2ejAlDYr/ZyEv7zF82++DtEKWLT
Bk6ae/uTWBYrsUnRYa92lbD3gEehlazgacCezs6Q
Hog9EAguCXOz7n69iJ3qExatDP9Gd+Ny1P8ymdn+
C4mkKoTeLvpqpVYmidPJD6j5hoyitZl/45SjuUUe
oKZkN9Fxkr8eSrNUJe4+j9wT75WEe8XCACpNwibe
iWxYjKUwpJMIrPQPt3dYzi67AWOkLudtzwGAEf/c
21CMzT6GrZ4VXXwwc1vKuDhOEbrXcLKK0osNquHv
WZNVYz8TZNOFnCSpVC4DkVwzdTPygtVBDdDhqH7Y
FxsuD09/8QXUTS0zWlDMMDSSt29zNhgMJchxBeNS
Ucb0Ei0H+6TOMdU5CztAxcmlGuQOElYTKH4WDc4c
07MWz4nNaYOZ48BgNhRQ3D0EkO1yLq7lZ2lwqFtM
MCseHCgmZPSbsqIENk5+0HRUHet5QXJwPvnoTgJF
2ZWNhgiXRP5m55Oen53uD7ETDeQu3g7F6yFCxeO1
Bx+z5IRbpXLi41sceo18l5mr2P/t8mjtBkC9RttR
Lu0j3BF9+fXIKIsCxROniMxD4ns05aQ3QdxNKYQK
RILFou4d/1IwnjtcyubIt/B7Gii2Ilb5FPfp7va0
HYobZEFiyqEZEBcspAnDe5Y86KmeUT9AQLzJ44GJ
5h8jtp/muoE5RMTjfOH/MmbQHtnBl0uTo6vhRbiz
18ytxs2ivEK8UWKEEZV1j+rR9Sbq0aQk1JCcAD9P
TjtWuhGvmB/lZta2vGFdQeYKlNLbDFPpPm8gUa/R
YOpDGx9dnr8O+kX4PZT6yhZvmry2jK8DLLpjfme9
zxvhkohbjlyZuLVP22jdU6F9GAzMJb/Z93sli8lc
5HZDSNWcBEAPHQ5FpZ7JW2k88/rf+3Yr61Kr0n7+
DApYOvu66+1eYfDQ3hBTrvYqZl7xuDsLTeVVHZYs
kdgTV7VYXfVfX9D8P4vUwP7f+om0ZVkISgkTK5HP
aq05qT2YoOZfB4al9G89LYE67MmU56nq5s0lWG8v
ZWmxj79z5S5diCUX8eaJp2NPtMuW7ShyQLNyloYs
Pt6NPAO5d4iQf3LMD0bZp73AtKG2Fh4b5qbUQRT9
ZJV0rBzVDviMRKAQeQuUI7S8ZUbfUu0+RiNHOLEN
Bw3i/4em+gGsf6oWQVO9bwHI+ylfD5a92tq/sBMA
6QMxd69OhX33qH6kmwbgSdEvpe9vKcD/9d8B44RK
d+MDO02VvU0VhherYU40trHsv3XaYonG0pqMrVH9
xgzN23fnQf8yTa/pPqAI6xVgL4y+8aWBqY9+5RWy
6Sk72oV/hN/CyilyfhLkn3K82yFZYcVCClvf2TLo
3X16msOWBfZfxopa0bdw2hd/nbtQWHmEu9wAvBWM
9aPLAOHSqnLAjh0kC7Lrp4PpWFB7MJmUp87gFPkg
QAsUydCNMBBs8qtSuum3SdUOMZn74i7uhHh/I8Zl
6XppFWa8t2Me1QJ9fVV/uUcVq6Uf2b0G4r+GGUpO
LbF4PhLeaGid2a5p/MA+J2b5cdOcEY2rLsyfwm+w
tFRH+FuzT9+RCefI0Rx/GC++yxgXdU4egKJPkudX
5r3la+77VDRXRbhzxEv+GuMFDeSw8QcvhuRzMa66
O1G0rtvFB7Za3KLWu8k5g8nRqg17jHzeLlfqz+TP
KO/0sUyYoR64iHukZkP6dHFWNbBx1GgWuS0/84bc
uI8yCW4/cANP4zt1bOJmldtsQtaB8Xrw0jGYDW5i
q0qosOCTy6tXTUBpRUJ5l692ZlVo3+z6ok0L8IDN
A/wFSHb2UjhFqz/jEhxM+SQzn9sW80SOzWmq6/Pj
Gp4M/in7CtSPGqqgjQYqLhafsKWzUwK1N7edvW1K
KNOl95Dk//DEeXsLja2+ZEPqmHNFqSxo+2rnw/Bs
RPcLo7o+Sqtqa2KbxDw5zzK2lGS8LRF8BDaHfVEo
BHU2GHspW01z7CAIlqzcgho23DoSRUYGCDhPQhD7
7iksZNy45gKcCXM+6Q7BEbf7OWxvu561Ck3EnBDh
A9fl7B5MXC7tKUjFjPbPixCoE5DLtyVBkPkb16EE
tPNIjaRSMrk/SiUjgYcAzht+RhjRZI9bUUvifwQp
ZJftZ7LieqoZcIQ512O0e/4lFASKkiwbsZr57ayq
CSi6QpMfiM5ZinYczwb0SxPVWqznfSPczR1LOGBw
l/+rgghTQb68TF7UkDBW3M3nsHnjxSyiugQFnGvh
aWfFlySeP1x7Rksgh3FCX+N/l1yJfmesk2WpkGbi
nBaJ8SRBp9LYDL+2x8XxJd0Ufc1CEx8Um1mw9Ayp
4aSgj+OiCIe1t90o57mb9Regr1ZEnbzlUj8+o/VM
ZzGN/gcCZpvpobmuIEsQ3Xp7fBTRLI2og+WgOy+J
jJmyMLjdIc7a/v8Tu7+ZlT30ia4HesLLNTUd2sHW
kPJtQrRXnYzA+4tNkDAd8Z5LU7tAxSkwSZ22snnJ
Di9W6LDtAwvAbaS364xTLYbkQ+CQeCxp9a1irtoI
5jWxfNX7SQX7Y79JA4LUJaa7Sv7fARLwF4LgVL30
871XEUyyznB+n9fFOCGjLJcuDfMfrVX1yZwPAPDy
X9ApKY3Vviigdv6u7UhYKEyiJ89b1tZ7rDGZ0Ajp
b1NiZK9fE7qBjfC7gvFBRcNfb0MHKlmaDXhUJ9lz
sZlz5lVMTTQyDy0xjkexsT2p0/Oiqw9h2YzriQUx
swzdYWuWNAh3mPKOMpiIyWSJiMxFtzlH9GZc9Ktb
khHcaIetm0Kd3l6rhqAu3N8FlCUxTrRFvLT8vRWW
GGx8vbU799SFvqk5oZSP7NrZlJPhl33k9J6TVVrU
7T3w/0Zf2W88NVfLWR8EQXlZf6ajoaAAMH6zFuWn
1WACmxfNT2dldiklAygfw17EghNEE0zt5DecyHv8
lG01JKVCC7fWRr3K3Zu2HIBSE1YjfcPymSITtR5c
jpAiUXn0cJB2Fj9fFKDMLtDPYRXmqgYHvP2FTByZ
4QNQwIlgi523XYiOKzAJinpQJV3qRCCS2ui+dHi7
cdgM6c72VKXcUYdnuND5SbpB4PfhDW6Jn3323sob
1wO7yc+wkh12crIjJQf19j7ZOjzYAePWaswCoPkV
1mnhTkJv9gAI6Zipo2PqtzkiPlaWpq7z7p6T1wI0
7IDGcPOFZtzHzHK37LPeMqTWIsNVtWaPbeH1CuMU
JD0EHno0zTxLJ42ufFUnnmFyT3uXgubXhVhBivqg
yxP5k42acErJxH8kaH51PkEr7Ol0g/+0aATmdn7x
oV6VeFdTVJKe5KsLyHb/TIxgmeQOAQuDUCD2ZcFI
CMFVoa8Rs9i2qFKUKAYH2QZCT3dioRwWqD78NFTP
N2kkaoWOA8aq7ubFjdlkYYY8oXY5rUwzI/9wdy7G
nfLWgy0C8duaXAdGvJsA0uIm234AuMygeappgR1a
zKkrIpLLOFZna3bFSjZRW8HwdeJMrj14/+Zwv6D4
A0j8GPu6UlUHBkJIWT0F7y0NGrM0m1sg4yGw6JMM
xXISOz5ttf0rXeXlhejxD98UeG1RWzAg1OvfOz+8
+vsY8ETSfBXWbuugtD9i2F/hv+FtmwHbRPUmE8sv
dfuFt6z5lLelGuypxzKEAHI9SGUPeDDPa1Yxi6xM
4rbu49uLXrdM9tVbGo2T4YBbYge8Bk72fWkktDMt
35wo6UcFJZuXp/9p+9ZvKOWiScx3k9182MwljekL
8mdq2TFzG8rJkCa2HD5sURvPIpvzp2bpG4L3avIT
IilGqaq7lJXAVcj37LJKidku8QIeOtCz1qC52+fj
aqQOcjwxY2HCH6VXN/15F0aRLNQIxFTcWEsReVh5
Oi3iCcp00ApTJ5mNMcf5z8NZscOCu3iYpGu26v/m
0+H9CkVl9qB3lE93nIthgQIOTtL7PBsSPjpVVpLn
rV6+cH5qqsHQwzBgnc7mNjCXuyQskdF44fFPPKMv
LbeJ/CiWrcMvfFgTZ+oAxtq75Ve3eHvGfOyv20cK
HXcCAjYAVLkqrCHYKj96DX4GvJM5V8QIPdpWNYR/
tvw9hh7OesoSlXzhnlDAc+Ak56snV/tt7Av2d2JT
YF+H8g02aOqzafNJ/sRXVKkC1UV5v3cvUt8lsDd4
oZhr0ktEc3HfcJ91vtjM/QuzBrdSgOG1gkPvX0US
tPOIN9aPqELbP/+5EkFDM1cDWv0x+9TRKITlfR/T
yaLWU6mD/BPilXiXviwkt0SqTttYCVIoU8Uok7LU
+qzoVHZxM9dFOGMbAPIBNNSKhXPgtGV6UXscAJba
6eq8z7gRMWP46y5U42E1M8WXBUfHYUva5JM+PLMT
mhrzKYrLJ2fMT5E/xEBC6M/mDRE8twUAybKBJ8Di
Y8SiGGBt9FGfgZGZw0J3qiEWTTMUWUm8F2K1dCM2
cBKZxNzZ13PPBryWDK6ggknnx6SRKs6FMXhJBUjd
yICMrrqkJxPnp6dM1u7ZReg3ZuCPfeUOx3TqyCs9
F9kHaT32Jdx7T3DwyulARuV7XOOZimlTC5tCnZVp
IuIDg4J2HHE6ZK4Z90mraf6ChHbiVhFmRNFs+97J
R+Rkw2zXARwhEfJlNGfBU+fPwzzAwoQ872HmBF1/
wwXU7Kp5Ovo2RqKCSuQ7axGJc/duptgoFRS9GNte
OFnQKb4uCgLR6EUffDXmBnVC763VYl8rEd6UMKlz
IDNHxmVtGOZCkd5Cy2nNu4JdZESSDRVyh2/Z9s35
JtShoL4DblnX8FzJ85cveuIN/7fJvUo3prQHr35q
SS5pEd216yCgv92mGhkaar2HqBlevDPN1PX7GM0u
3sSYzA7R2DH8ynUGX/YrMXAEnfvHPpI06duBwMxB
rYogc8aldU8PVen0BhNVY/v+Ehz53Rg8QBsvoS5L
0CDTSrmzc3Z3s9WpahGYBp8EMNxp1S1BVZ6u7l6J
BDCw8RbirPqQA80NmycHXo2DnanTxXmtgDsDPT1U
jJmiE1AyCr/4HZ7YO1ANRZwdIN4DEOEt0yJOfRWI
dYWhagQoVzHTFYmpAz4uBJ3bZJhWN0J8pdBxm/WZ
4uFVfGnSGrIBRUftLlgQLakx/6NrNgNoNmwS76li
0t20/+IFmCBuS1TPSXHm574l4QQ78iO+5h46M5/8
Chy6x+OPKWoWZaeedturqzGoDHPQkjnIPWa24Ze3
veaE9N0n1KSLD3Bz80bZdmC77eTgtrDezbCY85dP
3MlkvYI6PjZoH7H2GYYkyl71C9l36Hq+IZsm47vn
rP7Owk66OsLo4N7C7TUxt7ekiHAqOurEpcdAIGc2
UajRCh0Hdhop6BQuWWk0Enkqj/W9tP1v8LjRg4pr
qkp2VJOCLU9qqUEHOHjc1/h5JUdEq9RUv6G9ptDF
F709Tk9D27EYBAH8uyX6UPeBFVrN2HR+lVCO+t3h
Ptym7mGfJpQmintB13c8h3y6Twu/+jeLWqwBQvnb
cFnRHCs+4Fqq0EXGvuWFKz9b8ulEVJAdmTK7aqwS
dcWhRYsNdkFIOlZg0XnnCPbmH6VBfFkbgWvQHAqx
H3n6+gDgK/mtp+aMJwheT7Ajc9t2smagoG1nzhH6
qv/GraQJRukP0e6PWhIy/mEbp7Srz1pLs653tKch
2IcCP4e47ZEvfaIApsW8X2nIphBVMXcRZZQTBqFa
iChTu0COf3Pup4i82RyXV4kFX9QT3dZt6Rv+OpPe
0Cjg1oNsuTnHy33JM+Mw1It7PUxketnKmcGg/Irl
af3ReZeJ9FRBT2ow0DOxNucoPv6CnfhJEuLkcTMt
UkCBSLWJTs1DzANCrMStSlO+PnA8QbsRqgD2L2Bz
EZIoOoBEf1CQ9623CVeyEmWzufD+QpAO7RjxprTV
EhTOguk4GRGj935WSkqD0EVM0An/ndxSOc1H9vSr
lbi38Vghfy/V7dRAKMEvZuT+du6sQtSsaflR9twR
2q56kOvGliK/NdmuniA2EzxppadFWGl014I2beHC
0JQ3IwFO6oeQehYnnMWzijw1KaYAHDSLg9ruW4GN
NBnrpeVVHcDXEI6GegoeZRLA3nU7HiIlTkQYQsAS
oj7LVQakuaGaJrACgCrS8cms6Gk35ezSyHHNagX8
w1C0IAm5fEwlasiXdRU9rfm8lKGSAnH03aI7FHMf
x51o9naemP+WgRgO4LLsswlPInkVMD3NJowbgauS
Sj+pFX9gfA1ANstr+pibIJ4Q1hOuVNY7iIomB9Zw
kKVpByHU3ySGjmV0yB2kTZMBOq2Sr8f2DmI0urab
MZ34PUkr0fAYxOCXnDgyashyY5Gj67ca8bogRG8C
Mb7EDbSNoo703oACfxEqK5vUDtkICKKNmvSlCxQI
Fzx10cqACtiYJFawZVsTD4IF5fMDQMZZVibdm05C
j2og2d1i+nPwxVi6NK9QSnuc6+DJhbUD8gHjpwCT
IksLdtHuEt3ARVLSRbrSq/mxzIbUdsDZTM1Ceh0s
YAKV/OfbpHSaDLOV0a7Ouzp2mO47GZVAXglaoIs6
eOmSn+ewuTBllmjHuZqG9/gKi9Kjv5fZp3WoEox4
H35S5QknAYHBfqpB3toqaXbmj//fmR7bkVZC789J
A8t8+uE+ZggxSwBg9mcdQDGr5BQJg7B2MpmLfJ3K
MFYwmLP1b3ZJ1vRPX2v1BwkM6/mbr7UYmBDA/dCe
YwPsRSkcu5Z4tsr/EPUXEuNqIxBkliAV1CS9iO1l
TGTMVREX97xMdskVYNfjQ1S/yi9F+qhnAseKFaFy
7HMpu2FjNOcM4dsOvneBrVQ5BgwIIPRAHFsqyveg
T1hkhQvNZXQWQ5MIV/bC1Tv2pwkKFsD6Q++KknbK
Nu5U2P/hKQ4zbisuHDX3dX6Vm9ejW5l4p7DTb6q8
kGTSCGdYc+cLYg4Lk0XiH7q3Y2RHDVWaK0NvwUqW
pyYczB6RBkndzwqHBtzM0aYMXA29O6hmVoa7M2pC
esedKk3AoB8c5/oA4V0FgJ1GS04D0Q/+oyIAD9wO
1QxFP0VWHzLwVNkukyKQI0E3NZol+iEnVmJh2L+P
JnDe1QshIzqA6nbO+NX5Yj7cngl3o0YmsXta1obz
Z8LdWYhrsopT9plitUV8LTZQ3VPmrGxkCDVoFsBi
M+Ni5ktAGTYQksopVucjMcXJ2xTyBH5aqzuIR/oI
XLfLygLjoCvNS2o43J6t3UC77ng=
-----END REMAILER MESSAGE-----"""

config = Config.Config().config
#body_test()
h = HeaderUnpack()
test = test_message.decode("base64")
h.unpack(test[0:481])
print h.packet_type
print h.packet_info
