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

import sys
import os
import os.path
import logging
import shelve  # Required for packetid and chunk logs
from Config import config
import Utils
import timing


class PacketID():
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
            log.info("Performing daily prune of packetid log.")
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


class ChunkID(object):
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
        if timing.now() > self.nextday:
            log.info("Performing daily prune of partial chunk log.")
            for messageid in self.pktlog.keys():
                if self.pktlog[messageid]['age'] > self.pktexp:
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
                    log.warn("%s: Pool filename does not exist during chunk "
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
