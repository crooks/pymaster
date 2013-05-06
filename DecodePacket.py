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
import shelve  # Required for packetid and chunk logs
import zlib  # Mixmaster supports gzip payloads
import email.message
from Crypto.Cipher import DES3, PKCS1_v1_5
from Crypto.Hash import MD5
from Crypto.PublicKey import RSA
import Crypto.Random
from Config import config
import EncodePacket
import KeyManager
import Utils
import timing


class ValidationError(Exception):
    pass


class DummyMessage(Exception):
    pass


class DestinationError(Exception):
    """Raised when a Middleman remailer doesn't explicitly accept a stated
    destination"""
    pass


class MixPacket(object):
    def __init__(self, destalw, destblk, headalw, headblk):
        self.destalw = destalw
        self.destblk = destblk
        self.headalw = headalw
        self.headblk = headblk

    def unpack(self, packet):
        """Take an encrypted Mixmaster packet and split it into its component
           parts: The 20 headers and the payload.
        """
        assert len(packet) == 20480
        fmt = '@' + ('512s' * 20)
        self.set_encheads(struct.unpack(fmt, packet[0:10240]))
        self.set_encbody(packet[10240:20480])

    def set_encheads(self, encheads):
        """A list of 20 Mixmaster encrypted headers, each of 512 Bytes.
        """
        assert type(encheads) == tuple
        assert len(encheads) == 20
        self.encheads = encheads

    def set_encbody(self, encbody):
        """The 10240 Byte Mixmaster encrypted payload.
        """
        assert len(encbody) == 10240
        self.encbody = encbody

    def set_dhead(self, dhead):
        """The 328 Byte decrypted header section of the top 512 Byte header.
        """
        assert len(dhead) == 328
        self.dhead = dhead

    def set_dbody(self, dbody):
        """The decrypted payload.  In the case of an Exit message, this will
           be plain text.  For intermediates just the outer layer of
           encryption will be stripped.
        """
        # If a body gets here with a length other than a full Mixmaster
        # payload, it's either corrupted or about to be corrupted.
        assert len(dbody) == 10240
        length = struct.unpack('<I', dbody[0:4])[0]
        # We retain the length so it can be prepended to dbody again, should
        # the message require randhopping.
        self.length = dbody[0:4]
        self.dbody = dbody[4:length + 4]

    def set_chunk_dbody(self, dbody):
        """Nearly identical to the set_dbody function.  In this instance
           the payload is expected to be 10236 bytes as the length has already
           been processed on each chunk before storing them.
        """
        assert len(dbody) <= 10236
        if len(dbody) != 10236:
            log.warn("Processing a first chunk message where the payload "
                     "is less than a complete 10236 Byte packet.  Why is it "
                     "a chunk message?")
        self.dbody = dbody

    def append_dbody(self, dpart):
        """This is used during chunk reassembly to concatenate message
           components.
        """
        self.dbody += dpart

    def set_dests(self, dests):
        """This is the list of up to 20 destination addresses the message may
           be sent to.  It's only created for exit type messages.
        """
        assert type(dests) == list
        if len(dests) >= 1 and dests[0].startswith("null:"):
            raise DummyMessage("Dummy message")
        self.dests = self._dest_allow(dests)

    def set_heads(self, heads):
        """This is the list of up to 20 header fields that may be appended to
           the message.
        """
        assert type(heads) == list
        self.heads = self._head_allow(heads)

    def set_payload(self, payload):
        """The actual message payload.
        """
        assert type(payload) == str
        if payload.startswith("\x1f\x8b"):
            log.info("Payload begins with GZIP signature")
            chunksize = 1024
            d = zlib.decompressobj(16 + zlib.MAX_WBITS)
            length = len(payload)
            sbyte = 0
            outstr = ""
            while sbyte < length:
                ebyte = sbyte + chunksize
                if ebyte > length:
                    ebyte = length
                bufstr = d.decompress(payload[sbyte:ebyte])
                outstr += bufstr
                sbyte = ebyte
            outstr += d.flush()
            self.payload = outstr
        else:
            self.payload = payload

    def _dest_allow(self, dests):
        """Read the list of destinations defined in the message.  Strip out
        any that are explicitly blocked and return a new list of allowed
        destinations.  If any one is not explicitly allowed and we're running
        as a Middleman, raise a DestinationError and randhop it.
        """
        alw_dests = []
        randhop = False
        for d in dests:
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
            elif config.getboolean('general', 'middleman') and not alw:
                # The dest is not explicitly allowed or denied.  As this is
                # a Middleman.
                log.info("%s: Middleman doesn't allow this destination.", d)
                raise DestinationError("Must randhop")
            else:
                # No explict allow rule but we're not a Middleman so accept
                # the stated destination.
                alw_dests.append(d)
        return alw_dests

    def _head_allow(self, heads):
        """Read the list of destinations defined in the message.  Strip out
        any that are explicitly blocked and return a new list of allowed
        destinations.  If any one is not explicitly allowed and we're running
        as a Middleman, raise a DestinationError and randhop it.
        """
        alw_heads = []
        for h in heads:
            alw = self.headalw.hit(h)
            blk = self.headblk.hit(h)
            if alw and not blk:
                alw_heads.append(h)
            elif blk and not alw:
                log.debug("%s: Header explicitly blocked.", h)
            elif blk and alw:
                # Both allow and block hits mean a decision has to be made on
                # which has priority.  If block_first is True then allow is the
                # second (most significant) check.  If it's False, block is
                # more significant and the destinaion is not allowed.
                if config.getboolean('general', 'block_first'):
                    alw_heads.append(h)
                else:
                    log.info("%s: Header matches allow and block rules but "
                             "configuration dictates that block takes "
                             "priority", h)
            else:
                alw_heads.append(h)
        return alw_heads


class Mixmaster():
    def __init__(self, secring, idlog, chunkmgr):
        self.destalw = ConfFiles(config.get('etc', 'dest_alw'))
        self.destblk = ConfFiles(config.get('etc', 'dest_blk'))
        self.headalw = ConfFiles(config.get('etc', 'head_alw'))
        self.headblk = ConfFiles(config.get('etc', 'head_blk'))
        self.remailer_type = "mixmaster-%s" % config.get('general', 'version')
        self.secring = secring
        self.idlog = idlog
        self.chunkmgr = chunkmgr

    def email2packet(self, msgobj):
        """-----BEGIN REMAILER MESSAGE-----
           [packet length ]
           [message digest]
           [encoded packet]
           -----END REMAILER MESSAGE-----

           The input to this function is a Python Email object.  That's split
           into a list of lines and the base64 payload is extracted.  This is
           decoded, validated by length and digest and then stored in a
           MixPacket object.
        """
        mailmsg = msgobj.get_payload().split("\n")
        if ("-----BEGIN REMAILER MESSAGE-----" not in mailmsg or
            "-----END REMAILER MESSAGE-----" not in mailmsg):
            raise ValidationError("No cutmarks on this message")
        begin = mailmsg.index("-----BEGIN REMAILER MESSAGE-----")
        if begin > 10:
            # Bounces frequently contain the Remailer messages.  Checking if
            # the cutmarks are deep in the message is a good test.
            raise ValidationError("Cutmarks not in top ten lines of payload")
        end = mailmsg.index("-----END REMAILER MESSAGE-----")
        if end < begin:
            raise ValidationError("Reversed cutmarks")
        length = int(mailmsg[begin + 1])
        digest = mailmsg[begin + 2].decode("base64")
        packet = ''.join(mailmsg[begin + 3:end]).decode("base64")
        if len(packet) != length:
            raise ValidationError("Incorrect packet length")
        if digest != MD5.new(data=packet).digest():
            raise ValidationError("Mixmaster message digest failed")
        # This is the only place a Mixmaster Packet object is created.
        packobj = MixPacket(self.destalw,
                            self.destblk,
                            self.headalw,
                            self.headblk)
        packobj.unpack(packet)
        return packobj

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
         pad) = struct.unpack('@16sB128s8s328s31s', packet.encheads[0])
        if not len(sesskey) == datalen:
            raise ValidationError("Incorrect session key size")
        keyid = keyid.encode("hex")
        log.debug("Message is encrypted to key: %s", keyid)
        # Use the session key to decrypt the 3DES Symmetric key
        seckey = self.secring[keyid]
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
        # Here we set up the email message object that will eventually be
        # returned.  Regardless of the message type, the output will always
        # be an email message.
        (packetid,
         deskey,
         packet_type) = struct.unpack("@16s24sB", packet.dhead[0:41])
        #if self.idlog.hit(packetid):
        #    raise ValidationError('Known PacketID. Potential Replay-Attack.')
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
            # The payload string will be extended as each header has a layer of
            # encryption striped off.
            payload = ""
            # Loop through two components of the message, in parallel. The IVs
            # are extracted from the encrypted packet and the corresponding
            # encrypted header has a layer of 3DES removed.
            assert len(ivs) == 19
            assert len(packet.encheads) == 20
            for h in range(19):
                # Decrypt each 512 Byte packet header using the 3DES key and a
                # sequence of IVs held in the packet information.
                desobj = DES3.new(deskey, DES3.MODE_CBC, IV=ivs[h])
                payload += desobj.decrypt(packet.encheads[h + 1])
            # At this point, the payload contains 19 headers so the length
            # should be 19 * 512 Bytes.
            assert len(payload) == 9728
            # Add a fake 512 byte header to the bottom of the header stack.
            # This replaces the first header that we removed.
            payload += Crypto.Random.get_random_bytes(512)
            assert len(payload) == 10240
            desobj = DES3.new(deskey, DES3.MODE_CBC, IV=ivs[18])
            payload += desobj.decrypt(packet.encbody)
            assert len(payload) == 20480
            # This email object will be populated with the message for the
            # next hop remailer.
            msg = email.message.Message()
            msg.set_payload(self.mixprep(payload))
            msg['To'] = addy
            f = open(Utils.pool_filename('m'), 'w')
            f.write(msg.as_string())
            f.close()
        elif packet_type == 1:
            """Packet type 1 (final hop):
               Message ID                     [ 16 bytes]
               Initialization vector          [  8 bytes]
            """
            log.debug("This is an Exit type message")
            self.validate(packet, 65)
            message_id, iv = struct.unpack("@16s8s", packet.dhead[41:65])
            desobj = DES3.new(deskey, DES3.MODE_CBC, IV=iv)
            packet.set_dbody(desobj.decrypt(packet.encbody))
            self.unpack_body(packet)
            # This email object will be populated with the message for the
            # final destination.
            msg = email.message.Message()
            msg.set_payload(packet.payload)
            # This may require a little refinement but for now it seems to
            # fit the requirements.
            msg['To'] = ','.join(packet.dests)
            for h in packet.heads:
                head, content = h.split(':', 1)
                msg[head.strip()] = content.strip()
            f = open(Utils.pool_filename('m'), 'w')
            f.write(msg.as_string())
            f.close()
        elif packet_type == 2:
            """Packet type 2 (final hop, partial message):
               Chunk number                   [  1 byte ]
               Number of chunks               [  1 byte ]
               Message ID                     [ 16 bytes]
               Initialization vector          [  8 bytes]
            """
            log.debug("This is a chunk-type message")
            self.validate(packet, 67)
            (chunknum, numchunks, message_id,
             iv) = struct.unpack('@BB16s8s', packet.dhead[41:67])
            desobj = DES3.new(deskey, DES3.MODE_CBC, IV=iv)
            packet.set_dbody(desobj.decrypt(packet.encbody))
            ready_to_send = self.chunkmgr.bucket(message_id, numchunks,
                                                 chunknum, packet)
            if ready_to_send:
                # It's message reconstruction time!  First we need to retrieve
                # the first chunk; it contains the headers.
                self.chunkmgr.assemble(message_id, packet)
                self.unpack_body(packet)
                # The message object is now constructed from the first chunk.
                msg = email.message.Message()
                msg.set_payload(packet.payload)
                # This may require a little refinement but for now it seems to
                # fit the requirements.
                msg['To'] = ','.join(packet.dests)
                for h in packet.heads:
                    head, content = h.split(':', 1)
                    msg[head.strip()] = content.strip()
                # The message is now written to the file in the usual manner,
                # except that before closing it, we append all the other
                # message chunks to it in sequence.  This approach saves
                # reading the potentially ~2.5MB payload into memory.
                f = open(Utils.pool_filename('m'), 'w')
                f.write(msg.as_string())
                f.close()
                self.chunkmgr.delete(message_id)

    def unpack_body(self, packet):
        """Length                         [       4 bytes]
           Number of destination fields   [        1 byte]
           Destination fields             [ 80 bytes each]
           Number of header line fields   [        1 byte]
           Header lines fields            [ 80 bytes each]
           User data section              [ up to ~2.5 MB]
        """
        sbyte = 0
        ebyte = 1
        dfields = struct.unpack('B', packet.dbody[sbyte:ebyte])[0]
        if dfields > 20:
            raise ValidationError("Too many Destination fields")
        if dfields < 1:
            log.warn("No destinations on message")
            raise ValidationError("No destinations defined")
        dest_struct = "80s" * dfields
        sbyte = ebyte
        ebyte = sbyte + (80 * dfields)
        packet.set_dests(self.unpad(list(struct.unpack(dest_struct,
                                         packet.dbody[sbyte:ebyte]))))
        # At this point we have established a list of acceptable
        # email destinations.  Now for the header fields.
        sbyte = ebyte
        ebyte = sbyte + 1
        hfields = struct.unpack('B', packet.dbody[sbyte])[0]
        if hfields > 20:
            raise ValidationError("Too many Header fields")
        if hfields >= 1:
            head_struct = "80s" * hfields
            sbyte = ebyte
            ebyte = sbyte + 80 * hfields
            packet.set_heads(self.unpad(list(struct.unpack(head_struct,
                                             packet.dbody[sbyte:ebyte]))))
        else:
            packet.set_heads([])
        # We now have unpacked destinations and headers.  Now comes the
        # payload.
        sbyte = ebyte
        packet.set_payload(packet.dbody[sbyte:])

    def validate(self, packet, sbyte):
        """Encrypted headers are of varying length depending on type (Exit,
        Intermediate or Chunk).  This function validates the timestamp and
        digest on these types based on the provided sbyte index.
        """
        ebyte = sbyte + 5
        timehead = struct.unpack("5s", packet.dhead[sbyte:ebyte])[0]
        #TODO Remove this assertion after testing.  Correct formating of
        # inbound messages cannot be guaranteed.
        assert timehead == "0000\x00"
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
        checksum = MD5.new(data=binary).digest().encode("base64")
        length = len(binary)
        s = binary.encode("base64")
        s = ''.join(s.split("\n"))
        header = "::\n"
        header += "Remailer-Type: %s\n\n" % self.remailer_type
        header += "-----BEGIN REMAILER MESSAGE-----\n"
        header += "%s\n" % length
        header += "%s\n" % checksum
        payload = ""
        while len(s) > 0:
            payload += s[:n] + "\n"
            s = s[n:]
        payload = header + payload
        payload += "-----END REMAILER MESSAGE-----\n"
        return payload


class ConfFiles():
    def __init__(self, filename):
        # mtime is set to the Modified date on the file in "since Epoch"
        # format.  Setting it to zero ensures the file i`s read on the first
        # pass.
        mtime = 0
        self.mtime = mtime
        self.filename = filename
        log.info("%s: Initialized" % filename)

    def hit(self, testdata):
        if not os.path.isfile(self.filename):
            return False
        file_modified = os.path.getmtime(self.filename)
        if file_modified > self.mtime:
            log.info("%s modified. Recreating rules.", self.filename)
            (self.regex_rules,
             self.list_rules) = Utils.file2regex(self.filename)
            self.mtime = file_modified
        if testdata in self.list_rules:
            return True
        if self.regex_rules:
            regex_test = self.regex_rules.search(testdata)
            if regex_test:
                return True
        return False


class IDLog():
    """This class is concerned with logging Packet ID's in order to prevent
       replay attacks.  The ID is composed of 16 random bytes and these are
       used as the Key for the persistent dictionary (shelve).  The value held
       against each key is the date when the packetid was last seen.
    """
    def __init__(self):
        logfile = config.get('general', 'idlog')
        idlog = shelve.open(logfile, flag='c', writeback=False)
        idexp = config.getint('general', 'idexp')
        nextday = timing.future(days=1)
        self.idlog = idlog
        self.idexp = idexp
        self.nextday = nextday
        log.info("Packet ID log initialized. Entries=%s, ExpireDays=%s",
                 len(idlog), idexp)

    def prune(self):
        """Check if a day has passed since the last prune operation.  If it
           has, increment the day counter on each stored packetid.  If the
           count exceeeds the expiry period then delete the id from the log.
        """
        if timing.now() > self.nextday:
            log.debug("Starting PacketID Log pruning.")
            before = len(self.idlog)
            deleted = 0
            for k in self.idlog.keys():
                if self.idlog[k] > self.idexp:
                    del self.idlog[k]
                    deleted += 1
                else:
                    self.idlog[k] += 1
            self.idlog.sync()
            self.nextday = timing.future(days=1)
            after = len(self.idlog)
            log.info("Packet ID prune complete. Before=%s, Deleted=%s, "
                     "After=%s.", before, deleted, after)

    def hit(self, packetid):
        if packetid in self.idlog:
            self.idlog[packetid] = 0
            return True
        else:
            self.idlog[packetid] = 0
            return False

    def sync(self):
        self.idlog.sync()

    def close(self):
        self.idlog.close()
        log.info("Synced and closed the Packet ID log.")


class ChunkManager(object):
    """Mixmaster contructs outbound packets of equal size (20480 Bytes),
       regardless of the message size.  When the message content exceeds the
       capacity of a single packet, it's broken into chunks.  This class
       logs the packet chunks so the entire message can be reconstructed.
    """
    def __init__(self):
        logfile = config.get('general', 'explog')
        pktlog = shelve.open(logfile, flag='c', writeback=True)
        nextday = timing.future(days=1)
        pktexp = config.getint('general', 'packetexp')
        self.pktlog = pktlog
        self.nextday = nextday
        self.pktexp = pktexp
        log.info("Packet Chunk log initialized. Entries=%s, ExpireDays=%s",
                 len(pktlog), pktexp)

    def bucket(self, messageid, numchunks, chunknum, packet):
        mid = messageid.encode('hex')
        assert numchunks <= 255
        if numchunks < 2:
            log.warn("We have a chunk type message but with less the 2 "
                     "chunks.  That shouldn't happen during encoding but "
                     "it may be salvagable so processing will continue.")
        if chunknum > numchunks:
            log.warn("Chunk number exceeds stated number of chunks.  It's "
                     "unlikely there is a correct action to take in this "
                     "scenario but ignoring the chunk is probably best.")
            return False
        filename = Utils.pool_filename('p')
        # Use strings for dict keys as Integers may be unsupported.
        chunkstr = str(chunknum)
        if messageid in self.pktlog:
            if chunkstr in self.pktlog[messageid]:
                log.warn("Duplicate chunk number")
            if numchunks != self.pktlog[messageid]['numchunks']:
                log.warn("Message chunk reports a different total number of "
                         "chunks.")
            self.pktlog[messageid][chunkstr] = filename
        else:
            msgid_items = {chunkstr: filename,
                           'numchunks': numchunks,
                           'age': 0}
            self.pktlog[messageid] = msgid_items
        f = open(filename, 'wb')
        f.write(packet.dbody)
        f.close()
        # That's it for recording the packet chunk.  The rest of the function
        # is concerned with checking if all the chunks are available.  If they
        # are, True is returned.
        if len(self.pktlog[messageid]) == numchunks + 2:
            for k in self.pktlog[messageid]:
                # The items in the dict comprise 2 fixed items (numchunks,
                # age).  We therfore assume that when the item count is 2
                # greater than the numchunks, we have the entire message.
                for n in range(1, numchunks + 1):
                    nstr = str(n)
                    if not nstr in self.pktlog[messageid]:
                        log.error("A sufficient number of chunks are "
                                  "available but an expected chunk is "
                                  "missing.  This situation should not "
                                  "arise!  The missing chunk is: %s", nstr)
                        return False
            # We have a sufficient number of chunks and they are the chunk
            # numbers we expected.  Return True; we're ready to send!
            return True
        return False

    def assemble(self, messageid, packet):
        iditems = self.pktlog[messageid]
        numchunks = iditems['numchunks']
        log.debug("Reassembling chunked message using %s chunks.", numchunks)
        for i in range(1, numchunks + 1):
            infile = iditems[str(i)]
            content = open(infile, 'r')
            if i == 1:
                packet.set_chunk_dbody(content.read())
            else:
                packet.append_dbody(content.read())
            content.close()
        length = len(packet.dbody)
        log.debug("Reassembled a %s Byte message", length)

    def prune(self):
        if timing.now() > self.nextday():
            for messageid in self.pktlog.keys():
                if messageid['age'] > self.pktexp:
                    log.info("Deleting chunks due to packet expiration. "
                             "A message will be lost but we can't wait "
                             "forever.")
                    self.delete(messageid)
                else:
                    self.pktlog[messageid]['age'] += 1
            self.nextday = timing.future(days=1)

    def delete(self, messageid):
        """When a partial chunk expires, it's a safe assumption that other
           pending chunks of the same message are now useless.  This function
           attempts to delete all chunks that exist for a message.  This
           function also serves to delete partial chunks after complete
           message reassembly.
        """
        deleted_chunks = 0
        numchunks = self.pktlog[messageid]['numchunks']
        log.debug("Attempting to delete %s chunk files.", numchunks)
        for n in range(1, numchunks + 1):
            nstr = str(n)
            if nstr in self.pktlog[messageid]:
                filename = self.pktlog[messageid][nstr]
                if os.path.isfile(filename):
                    os.remove(filename)
                    deleted_chunks += 1
                else:
                    log.error("%s: Pool filename does not exist during chunk "
                              "deletion.  What happened to it?", filename)
            else:
                log.error("Expected to find chunk %s during chunk deletion "
                          "but there is no key for it in the chunk log.  A"
                          "lost packet chunk may sit in the pool forever.",
                          nstr)
        log.debug("Chunk deletion completed.  Removed %s chunks.",
                  deleted_chunks)
        del self.pktlog[messageid]

    def sync(self):
        self.pktlog.sync()

    def close(self):
        self.pktlog.close()
        log.info("Synced and closed the Chunk log.")


log = logging.getLogger("Pymaster.%s" % __name__)
if (__name__ == "__main__"):
    logfmt = config.get('logging', 'format')
    datefmt = config.get('logging', 'datefmt')
    log = logging.getLogger("Pymaster")
    log.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(fmt=logfmt, datefmt=datefmt))
    log.addHandler(handler)
    secring = KeyManager.Secring()
