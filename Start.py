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
import os.path
import logging
import mailbox
import email
import struct
from Crypto.Hash import MD5
from Config import config
from Crypto.Random import random
import DecodePacket
import Utils


class MailError(Exception):
    pass


class PayloadError(Exception):
    """Raised when a problem exists with the Mixmaster packet.
    """
    pass


class MailMessage():
    def __init__(self):
        maildir = config.get('paths', 'maildir')
        self.inbox = mailbox.Maildir(maildir, factory=None, create=False)

    def iterate_mailbox(self):
        log.info("Beginning mailbox processing")
        for k in self.inbox.iterkeys():
            try:
                self.mail2pool(k)
            except MailError, e:
                print k, e
            self.inbox.remove(k)
        self.inbox.close()

    def mail2pool(self, msgkey):
        mailfile = self.inbox.get_file(msgkey)
        msg = email.message_from_file(mailfile)
        mailfile.close()
        if msg.is_multipart():
            raise MailError("Message is multipart")
        if msg.has_key('Subject'):
            print msg['Subject']
        self.extract_packet(msg)
        f = open(Utils.pool_filename('m'), 'wb')
        f.write(self.packet)
        f.close()

    def extract_packet(self, msgobj):
        """-----BEGIN REMAILER MESSAGE-----
           [packet length ]
           [message digest]
           [encoded packet]
           -----END REMAILER MESSAGE-----

           The function takes a message object and splits its payload into
           component parts.  These parts are a list of 20 headers and the
           body.
        """
        mailmsg = msgobj.get_payload().split("\n")
        if ("-----BEGIN REMAILER MESSAGE-----" not in mailmsg or
            "-----END REMAILER MESSAGE-----" not in mailmsg):
            raise MailError("No Remailer Message cutmarks")
        begin = mailmsg.index("-----BEGIN REMAILER MESSAGE-----")
        end = mailmsg.index("-----END REMAILER MESSAGE-----")
        length = int(mailmsg[begin + 1])
        digest = mailmsg[begin + 2].decode("base64")
        packet = ''.join(mailmsg[begin + 3:end]).decode("base64")
        if len(packet) != length:
            raise ValidationError("Incorrect packet length")
        if digest != MD5.new(data=packet).digest():
            raise ValidationError("Mixmaster message digest failed")
        self.packet = packet


class Pool():
    def __init__(self):
        self.m = DecodePacket.Mixmaster()

    def process(self):
        for f in self.pick_files():
            log.debug("Processing file: %s", f)
            try:
                mixobj = self.read_file(f)
            except PayloadError, e:
                log.warn("%s: %s", f, e)
                continue
            try:
                msg = self.m.process(mixobj)
            except DecodePacket.ValidationError, e:
                log.warn("%s: %s", f, e)
                continue
            except DecodePacket.DummyMessage, e:
                log.debug("%s: Dummy message", f)
                continue
    
    def read_file(self, filename):
        fq = os.path.join(config.get('paths', 'pool'), filename)
        f = open(fq, 'rb')
        packet = f.read()
        f.close()
        if len(packet) != 20480:
            raise PayloadError("Incorrect Mixmaster packet size")
        p = DecodePacket.MixPacket()
        fmt = '@' + ('512s' * 20)
        p.set_headers(struct.unpack(fmt, packet[0:10240]))
        p.set_encbody(packet[10240:20480])
        return p

    def pick_files(self):
        """Pick a random subset of filenames in the Pool and return them as a
        list.  If the Pool isn't sufficiently large, return an empty list.
        """
        pooldir = config.get('paths', 'pool')
        poolfiles = os.listdir(pooldir)
        poolsize = len(poolfiles)
        log.debug("Pool contains %s messages", poolsize)
        if poolsize < config.get('pool', 'size'):
            # The pool is too small to send messages.
            log.info("Pool is insufficiently populated to trigger sending.")
            return []
        process_num = (poolsize * config.getint('pool', 'rate')) / 100
        log.debug("Attempting to send %s messages from the pool.", process_num)
        assert process_num <= poolsize
        # Shuffle the poolfiles into a random order
        random.shuffle(poolfiles)
        # Even though the list is shuffled, we'll pick a random point in the
        # list to slice from/to.  It does no harm, might do some good and
        # doesn't cost a lot!
        startmax = poolsize - process_num
        start = random.randint(0, startmax - 1)
        end = start + process_num
        return poolfiles[start:end]

log = logging.getLogger("Pymaster.DecodePacket")
if (__name__ == "__main__"):
    logfmt = config.get('logging', 'format')
    datefmt = config.get('logging', 'datefmt')
    log = logging.getLogger("Pymaster")
    log.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(fmt=logfmt, datefmt=datefmt))
    log.addHandler(handler)

    #mail = MailMessage()
    #mail.iterate_mailbox()
    pool = Pool()
    pool.process()
