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
import EncodePacket
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
        self.added_to_pool = 0
        self.remailer_foo_msgs = 0
        self.failed_msgs = 0
        for k in messages:
            try:
                self.mail2pool(k)
            except MailError, e:
                log.info("Mail Error: %s", e)
            self.inbox.remove(k)
        log.info("Mail processing complete. Processed=%s, Pooled=%s, Text=%s, Failed=%s",
                  len(messages), self.added_to_pool, self.remailer_foo_msgs,
                  self.failed_msgs)
        self.inbox.close()
        self.smtp.quit()

    def mail2pool(self, msgkey):
        mailfile = self.inbox.get_file(msgkey)
        msg = email.message_from_file(mailfile)
        mailfile.close()
        mixmail = DecodePacket.MixMail()
        name, addy = email.utils.parseaddr(msg['From'])
        if addy.lower().startswith("mailer-daemon"):
            f = open('/home/pymaster/bounce.txt', 'a')
            f.write(msg.as_string())
            f.close()
            raise MailError("Message from mailer-daemon")
        if msg.is_multipart():
            raise MailError("Message is multipart")
        try:
            # email2packet returns True if it successfully extracts a
            # Mixmaster packet from the supplied email object.
            ismix = mixmail.email2packet(msg)
        except DecodePacket.ValidationError, e:
            log.debug("Invalid Mixmaster message: %s", e)
            return 0
        if ismix:
            mixmail.packet2pool()
            self.added_to_pool += 1
        else:
            # If this isn't a remailer message, it might be a request for
            # remailer info.
            self.remailer_foo(msg)

    def remailer_foo(self, inmsg):
        if not 'Subject' in inmsg:
            log.debug("Non-remailer message with no Subject.  Ignoring it.")
            self.failed_msgs += 1
            return 0
        if 'Reply-To' in inmsg:
            inmsg['From'] = inmsg['Reply-To']
        elif not 'From' in inmsg:
            # No Reply-To and no From.  We don't know where to send the
            # remailer-foo message so no point in trying.
            log.debug("Non-remailer message with no reply address.  "
                      "Ignoring it")
            self.failed_msgs += 1
            return 0
        addy = inmsg['From']
        sub = inmsg['Subject'].lower().strip()
        if sub == 'remailer-key':
            outmsg = self.send_remailer_key()
        elif sub == 'remailer-conf':
            outmsg = self.send_remailer_conf()
        elif sub == 'remailer-help':
            outmsg = self.send_remailer_help()
        elif sub == 'remailer-adminkey':
            outmsg = self.send_remailer_adminkey()
        elif sub == 'remailer-stats':
            #TODO Not yet implemented remailer-stats
            self.remailer_foo_msgs += 1
            return 0
        else:
            log.warn("%s: No programmed response for this Subject", sub)
            self.msg2file(inmsg)
            self.failed_msgs += 1
            return 0
        outmsg["From"] = "%s <%s>" % (config.get('general', 'longname'),
                                      config.get('mail', 'address'))
        outmsg["Message-ID"] = Utils.msgid()
        outmsg['Date'] = email.utils.formatdate()
        outmsg['To'] = addy
        self.smtp.sendmail(outmsg["From"], outmsg["To"], outmsg.as_string())
        self.remailer_foo_msgs += 1
        log.debug("Sent %s to %s", outmsg['Subject'], outmsg['To'])

    def msg2file(self, inmsg):
        f = open("/home/pymaster/check.txt", "a")
        f.write(inmsg.as_string())
        f.close()

    def send_remailer_key(self):
        msg = email.message.Message()
        payload = '%s\n\n' % Utils.capstring()
        payload += 'Here is the Mixmaster key:\n\n'
        payload += '=-=-=-=-=-=-=-=-=-=-=-=\n'
        f = open(config.get('keys', 'pubkey'), 'r')
        payload += f.read()
        f.close()
        msg.set_payload(payload)
        msg["Subject"] = "Remailer key for %s" % config.get('general',
                                                            'shortname')
        return msg

    def send_remailer_conf(self):
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
        for h in EncodePacket.pubring_headers():
            payload += h + "\n"
        msg.set_payload(payload)
        msg["Subject"] = ("Capabilities of the %s remailer"
                          % config.get('general', 'shortname'))
        return msg

    def send_remailer_help(self):
        filename = config.get('etc', 'helpfile')
        msg = email.message.Message()
        if os.path.isfile(filename):
            f = open(filename, 'r')
            payload = f.read()
            f.close()
        else:
            payload = "No help information available\n"
        msg.set_payload(payload)
        msg["Subject"] = ("Help info for the %s remailer"
                          % config.get('general', 'shortname'))
        return msg

    def send_remailer_adminkey(self):
        filename = config.get('etc', 'adminkey')
        msg = email.message.Message()
        if os.path.isfile(filename):
            f = open(filename, 'r')
            payload = f.read()
            f.close()
        else:
            payload = "No adminkey available\n"
        msg.set_payload(payload)
        msg["Subject"] = ("Admin PGP Key for the %s Remailer"
                          % config.get('general', 'shortname'))
        return msg


class Pool():
    def __init__(self, secring):
        self.decode = DecodePacket.Mixmaster(secring)
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
            fq = os.path.join(config.get('paths', 'pool'), f)
            if f.startswith("m"):
                log.debug("Processing file: %s", f)
                try:
                    mixobj = self.decode.get_payload(fq)
                except DecodePacket.ValidationError, e:
                    log.warn("%s: Payload Error: %s", f, e)
                    self.delete(fq)
                    continue
                try:
                    msg = self.decode.process(mixobj)
                except DecodePacket.ValidationError, e:
                    log.warn("%s: Validation Error: %s", f, e)
                    self.delete(fq)
                    continue
                except DecodePacket.DummyMessage, e:
                    log.debug("%s: Dummy message", f)
                    self.delete(fq)
                    continue
            elif f.startswith("o"):
                fqf = open(fq, 'r')
                msg = email.message_from_file(fqf)
                fqf.close()
            msg["Message-ID"] = Utils.msgid()
            msg["Date"] = email.Utils.formatdate()
            msg["From"] = "%s <%s>" % (config.get('general', 'longname'),
                                       config.get('mail', 'address'))
            smtp.sendmail(msg["From"], msg["To"], msg.as_string())
            self.delete(fq)
        smtp.quit()
        # OUtbound dummy message generation.
        if random.randint(0, 100) < config.get('pool', 'outdummy'):
            log.debug("Generating dummy message.")
            EncodePacket.dummy()
        # Return the time for the next pool processing.
        self.next_process = timing.dhms_future(self.interval)
        log.debug("Next pool process at %s",
                  timing.timestamp(self.next_process))

    def delete(self, fq):
        """Delete files from the Mixmaster Pool."""
        os.remove(fq)

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

log = logging.getLogger("Pymaster")
if (__name__ == "__main__"):
    logfmt = config.get('logging', 'format')
    datefmt = config.get('logging', 'datefmt')
    log = logging.getLogger("Pymaster")
    log.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(fmt=logfmt, datefmt=datefmt))
    log.addHandler(handler)

    pubring = KeyManager.Pubring()
    secring = KeyManager.Secring()
    mail = MailMessage()
    pool = Pool(secring)
    sleep = timing.dhms_secs(config.get('general', 'interval'))
    while True:
        mail.iterate_mailbox()
        pool.process()
        log.debug("Sleeping for %s seconds", sleep)
        timing.sleep(sleep)
