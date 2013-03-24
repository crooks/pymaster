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
import smtplib
import struct
from Crypto.Hash import MD5
from Config import config
from Crypto.Random import random
import timing
import DecodePacket
import KeyManager
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
        self.server = config.get('mail', 'server')
        log.info("Initialized Mail handler. Mailbox=%s, Server=%s",
                  maildir, self.server)

    def iterate_mailbox(self):
        log.info("Beginning mailbox processing")
        self.smtp = smtplib.SMTP(self.server)
        messages = self.inbox.keys()
        log.debug("Processing %s messages from mailbox.", len(messages))
        for k in messages:
            try:
                self.mail2pool(k)
            except MailError, e:
                print k, e
            self.inbox.remove(k)
        self.inbox.close()
        self.smtp.quit()

    def mail2pool(self, msgkey):
        mailfile = self.inbox.get_file(msgkey)
        msg = email.message_from_file(mailfile)
        mailfile.close()
        if msg.is_multipart():
            raise MailError("Message is multipart")
        txtreply = self.remailer_foo(msg)
        if txtreply:
            log.debug("Responded to Remailer-Foo message")
        else:
            packet = self.extract_packet(msg)
            f = open(Utils.pool_filename('m'), 'wb')
            f.write(packet)
            f.close()

    def remailer_foo(self, inmsg):
        if not 'Subject' in inmsg:
            return False
        sub = inmsg.get("Subject").lower().strip()
        if 'Reply-To' in inmsg:
            inmsg['From'] = inmsg['Reply-To']
        elif not 'From' in inmsg:
            # No Reply-To and no From.  We don't know where to send the
            # remailer-foo message so no point in trying.
            return False
        addy = inmsg['From']
        if sub == 'remailer-key':
            self.send_remailer_key(addy)
        elif sub == 'remailer-conf':
            self.send_remailer_conf(addy)
        else:
            log.debug("%s: No programmed response for this Subject",
                      inmsg.get("Subject"))
            return False
        return True

    def send_remailer_key(self, recipient):
        msg = email.message.Message()
        payload = '%s\n\n' % Utils.capstring()
        payload += 'Here is the Mixmaster key:\n\n'
        payload += '=-=-=-=-=-=-=-=-=-=-=-=\n'
        f = open(config.get('keys', 'pubkey'), 'r')
        payload += f.read()
        f.close()
        msg.set_payload(payload)
        msg["From"] = "%s <%s>" % (config.get('general', 'longname'),
                                   config.get('mail', 'address'))
        msg["Subject"] = "Remailer key for %s" % config.get('general',
                                                            'shortname')
        msg["Message-ID"] = Utils.msgid()
        msg['Date'] = email.utils.formatdate()
        msg['To'] = recipient
        self.smtp.sendmail(msg["From"], msg["To"], msg.as_string())
        log.debug("Sent remailer-key to %s" % recipient)

    def send_remailer_conf(self, recipient):
        msg = email.message.Message()
        payload = "Remailer-Type: %s\n" % config.get('general', 'version')
        payload += "Supported format: Mixmaster\n"
        payload += "Pool size: %s\n" % config.get('pool', 'size')
        payload += ("Maximum message size: %s kB\n"
                    % config.get('general', 'klen'))
        payload += "In addition to other remailers, this remailer also sends "
        payload += "mail to these\n addresses directly:\n"
        #TODO SUpported direct delivery addresses
        payload += "The following header lines will be filtered:\n"
        #TODO Filtered headers
        payload += "The following domains are blocked:\n"
        #TODO Dest Blocks
        payload += '\n%s\n\n' % Utils.capstring()
        payload += "SUPPORTED MIXMASTER (TYPE II) REMAILERS\n"
        for h in pubring.get_headers():
            payload += h + "\n"
        msg.set_payload(payload)
        msg["From"] = "%s <%s>" % (config.get('general', 'longname'),
                                   config.get('mail', 'address'))
        msg["Subject"] = ("Capabilities of the %s remailer"
                          % config.get('general', 'shortname'))
        msg["Message-ID"] = Utils.msgid()
        msg['Date'] = email.utils.formatdate()
        msg['To'] = recipient
        self.smtp.sendmail(msg["From"], msg["To"], msg.as_string())
        log.debug("Sent remailer-conf to %s" % recipient)

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
        if begin > 10:
            raise MailError("BEGIN cutmark not at top of message")
        end = mailmsg.index("-----END REMAILER MESSAGE-----")
        length = int(mailmsg[begin + 1])
        digest = mailmsg[begin + 2].decode("base64")
        packet = ''.join(mailmsg[begin + 3:end]).decode("base64")
        if len(packet) != length:
            raise MailError("Incorrect packet length")
        if digest != MD5.new(data=packet).digest():
            raise MailError("Mixmaster message digest failed")
        return packet


class Pool():
    def __init__(self):
        self.m = DecodePacket.Mixmaster()
        self.next_process = timing.future(mins=1)
        self.interval = config.get('pool', 'interval')
        self.rate = config.getint('pool', 'rate')
        self.size = config.getint('pool', 'size')
        self.pooldir = config.get('paths', 'pool')
        log.info("Initialised pool. Path=%s, Interval=%s, Rate=%s%%, "
                 "Size=%s.",
                 self.pooldir, self.interval, self.rate, self.size)
        log.debug("First pool process at %s",
                  timing.timestamp(self.next_process))

    def process(self):
        if timing.now() < self.next_process:
            return 0
        log.info("Beginning Pool processing.")
        smtp = smtplib.SMTP(config.get('mail', 'server'))
        for f in self.pick_files():
            log.debug("Processing file: %s", f)
            try:
                mixobj = self.read_file(f)
            except PayloadError, e:
                log.warn("%s: Payload Error: %s", f, e)
                self.delete(f)
                continue
            try:
                msg = self.m.process(mixobj)
            except DecodePacket.ValidationError, e:
                log.warn("%s: Validation Error: %s", f, e)
                self.delete(f)
                continue
            except DecodePacket.DummyMessage, e:
                log.debug("%s: Dummy message", f)
                self.delete(f)
                continue
            msg["Message-ID"] = Utils.msgid()
            msg["Date"] = email.Utils.formatdate()
            msg["From"] = "%s <%s>" % (config.get('general', 'longname'),
                                       config.get('mail', 'address'))
            smtp.sendmail(msg["From"], msg["To"], msg.as_string())
            self.delete(f)
        smtp.quit()
        # Return the time for the next pool processing.
        self.next_process = timing.dhms_future(self.interval)
        log.debug("Next pool process at %s",
                  timing.timestamp(self.next_process))

    def delete(self, f):
        """Delete files from the Mixmaster Pool."""
        fq = os.path.join(config.get('paths', 'pool'), f)
        os.remove(fq)
        log.debug("%s: Deleted from pool.", f)

    def read_file(self, filename):
        fq = os.path.join(config.get('paths', 'pool'), filename)
        f = open(fq, 'rb')
        packet = f.read()
        f.close()
        if len(packet) != 20480:
            log.warn("Only correctly sized payloads should make it into the "
                     "Pool.  Somehow this message slipped through.")
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
        poolfiles = os.listdir(self.pooldir)
        poolsize = len(poolfiles)
        log.debug("Pool contains %s messages", poolsize)
        if poolsize < self.size:
            # The pool is too small to send messages.
            log.info("Pool is insufficiently populated to trigger sending.")
            return []
        process_num = (poolsize * self.rate) / 100
        log.debug("Attempting to send %s messages from the pool.", process_num)
        assert process_num <= poolsize
        # Shuffle the poolfiles into a random order
        random.shuffle(poolfiles)
        # Even though the list is shuffled, we'll pick a random point in the
        # list to slice from/to.  It does no harm, might do some good and
        # doesn't cost a lot!
        startmax = poolsize - process_num
        if startmax <= 0:
            return poolfiles
        start = random.randint(0, startmax - 1)
        end = start + process_num
        return poolfiles[start:end]

pubring = KeyManager.Pubring()
log = logging.getLogger("Pymaster")
if (__name__ == "__main__"):
    logfmt = config.get('logging', 'format')
    datefmt = config.get('logging', 'datefmt')
    log = logging.getLogger("Pymaster")
    log.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(fmt=logfmt, datefmt=datefmt))
    log.addHandler(handler)

    mail = MailMessage()
    pool = Pool()
    sleep = config.getint('general', 'interval')
    while True:
        mail.iterate_mailbox()
        pool.process()
        log.debug("Sleeping for %s seconds", sleep)
        timing.sleep(sleep)
