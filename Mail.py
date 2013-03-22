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

import os.path
import mailbox
import email
import smtplib
import logging
from Crypto.Random import random
from Crypto.Hash import MD5
from Config import config
import timing
import Utils
import DecodePacket
import EncodePacket
import KeyManager


class MessageError(Exception):
    pass


class Mailbox():
    def __init__(self):
        self.mix_decode = DecodePacket.MixPayload()
        maildir = config.get('paths', 'maildir')
        self.inbox = mailbox.Maildir(maildir, factory=None, create=False)
        self.next_process = timing.future(mins=1)
        self.interval = config.get('mail', 'interval')
        log.debug("Initialised mailbox.  First process at %s",
                  timing.timestamp(self.next_process))
        log.debug("Using Maildir %s.", maildir)

    def process(self):
        if timing.now() < self.next_process:
            return 0
        for k in self.inbox.iterkeys():
            try:
                self.read_message(k)
            except MessageError, e:
                log.debug("%s: Exception: %s", k, e)
            except DecodePacket.ValidationError, e:
                log.debug("%s: Validation Error: %s", k, e)
            except DecodePacket.DummyMessage:
                log.debug("%s: Deleted Dummy message.", k)
            self.delete(k)
        self.next_process = timing.dhms_future(self.interval)

    def messages(self):
        return self.inbox.iterkeys()

    def delete(self, key):
        # Using remove() instead of discard() so an exception occurs if a key
        # doesn't exist.  Nothing external should modify the Mailbox.
        self.inbox.remove(key)
        log.debug("%s: Deleted message from maildir", key)

    def read_message(self, key):
        """-----BEGIN REMAILER MESSAGE-----
           [packet length ]
           [message digest]
           [encoded packet]
           -----END REMAILER MESSAGE-----
        """

        mixmes = False
        # It's a reasonable assumption that headers are at the top of a mail
        # message.
        inhead = True
        subject = None
        msgfrom = None
        f = self.inbox.get_file(key)
        for line in f:
            if line.startswith("From: "):
                msgfrom = line.split(": ", 1)[1].strip().lower()
            elif line.startswith("Subject: "):
                subject = line.split(": ", 1)[1].strip().lower()
            elif line == "\n":
                if (subject == 'remailer-key' and
                    msgfrom is not None):
                    self.send_remailer_key(msgfrom)
                    break
                if (subject == 'remailer-conf' and
                    msgfrom is not None):
                    self.send_remailer_conf(msgfrom)
                    break
                inhead = False
            elif inhead:
                # Go no further than this until we're not handling headers.
                continue
            if line.startswith("-----BEGIN REMAILER MESSAGE-----"):
                if mixmes:
                    raise MessageError("Corrupted. Got multiple Begin "
                                          "Message cutmarks.")
                else:
                    # This is the beginning of a Mixmaster message.  The
                    # following variables are reset once a message is
                    # identified as a candidate.
                    mixmes = True  # True when inside a Mixmaster payload
                    line_index = 0  # Packet line counter
                    packet = ""  # Packet payload (in Base64)
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
        f.close()
        if mixmes:
            packet = packet.decode("base64")
            # Validate the length and digest of the packet.
            if length != len(packet):
                raise MessageError("Incorrect packet Length")
            if digest != MD5.new(data=packet).digest():
                raise MessageError("Mixmaster message digest failed")
            mix_payload = {'header': packet[0:512],
                           'headers': packet[512:10240],
                           'body': packet[10240:]}
            self.mix_decode.unpack(mix_payload)

    def send_remailer_key(self, recipient):
        smtp = smtplib.SMTP(config.get('mail', 'server'))
        payload = '%s\n\n' % Utils.capstring()
        payload += 'Here is the Mixmaster key:\n\n'
        payload += '=-=-=-=-=-=-=-=-=-=-=-=\n'
        f = open(config.get('keys', 'pubkey'), 'r')
        payload += f.read()
        f.close()
        msg = email.message_from_string(payload)
        msg["From"] = "%s <%s>" % (config.get('general', 'longname'),
                                   config.get('mail', 'address'))
        msg["Subject"] = "Remailer key for %s" % config.get('general',
                                                            'shortname')
        msg["Message-ID"] = Utils.msgid()
        msg['Date'] = email.utils.formatdate()
        msg['To'] = recipient
        smtp.sendmail(msg["From"], msg["To"], msg.as_string())
        logging.debug("Sent remailer-key to %s" % recipient)

    def send_remailer_conf(self, recipient):
        smtp = smtplib.SMTP(config.get('mail', 'server'))
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
        payload += '%s\n\n' % Utils.capstring()
        payload += "SUPPORTED MIXMASTER (TYPE II) REMAILERS\n"
        for h in pubring.get_headers():
            payload += h + "\n"
        msg = email.message_from_string(payload)
        msg["From"] = "%s <%s>" % (config.get('general', 'longname'),
                                   config.get('mail', 'address'))
        msg["Subject"] = ("Capabilities of the %s remailer"
                          % config.get('general', 'shortname'))
        msg["Message-ID"] = Utils.msgid()
        msg['Date'] = email.utils.formatdate()
        msg['To'] = recipient
        smtp.sendmail(msg["From"], msg["To"], msg.as_string())
        logging.debug("Sent remailer-conf to %s" % recipient)


class Sender():
    def __init__(self):
        self.destalw = ConfFiles(config.get('etc', 'dest_alw'), 'dest_alw')
        self.destblk = ConfFiles(config.get('etc', 'dest_blk'), 'dest_blk')
        self.desthdrs = ['To', 'Cc', 'Bcc']
        self.middleman = config.getboolean('general', 'middleman')
        smtp = smtplib.SMTP(config.get('mail', 'server'))
        self.smtp = smtplib.SMTP(config.get('mail', 'server'))

    def sendmail(self, msg):
        print msg['From']
        block = self.validate(msg)
        assert block >= 0 and block <= 2
        if block == 0:
            log.debug("Message passed destination validation.  Sending "
                      "directly.")
            return True
            #smtp.sendmail(msg["From"], msg["To"], msg.as_string())
        elif block == 1:
            log.debug("Destination is not allowed.  Rejecting message.")
            return True
        elif block == 2:
            log.debug("Message needs to be randhopped to another remailer.")
            #TODO Need to randhop this message.  Once that functionality is
            # sorted, this can return True so such messages are deleted.
            return False

    def validate(self, msg):
        """Validation must return three states.  Allowed, Blocked or Randhop.
           0    Allowed (The message will be delivered directly)
           1    Blocked (The message is rejected and deleted)
           2    Randhop (Try to pass the message to another remailer)
        """
        if msg['To'] in pubring.get_addresses():
            log.debug("Destination is another remailer. Allow it")
            if 'Cc' in msg:
                log.warn("Messages to other remailers shouldn't contain Cc "
                         "headers. Deleting header.")
                del msg['Cc']
            if 'Bcc' in msg:
                log.warn("Messages to other remailers shouldn't contain Bcc "
                         "headers. Deleting header.")
                del msg['Bcc']
            return 0
        alw_hit = False
        blk_hit = False
        for h in self.desthdrs:
            if h in msg:
                if self.destalw.hit(msg[h]):
                    alw_hit = True
                if self.destblk.hit(msg[h]):
                    blk_hit = True
        if alw_hit and not blk_hit:
            return 0
        elif blk_hit and not alw_hit:
            return 1
        elif blk_hit and alw_hit:
            # Both allow and block hits mean a decision has to be made on
            # which has priority.  If block_first is True then allow is the
            # second (most significant) check.  If it's False, block is more
            # significant and the destinaion is not allowed.
            if config.getboolean('general', 'block_first'):
                return 0
            else:
                return 1
        else:
            # This is the most common result.  The destination isn't
            # explicitly allowed or denied.
            if self.middleman:
                # This is a Middleman and the stated destination isn't
                # whitelisted.  Needs to be randhopped.
                return 2
            else:
                # This is an Exit Remailer.  By default we allow all email
                # destinations that aren't explicitly blocked.
                return 0


class Pool():
    def __init__(self):
        self.email = Sender()
        self.next_process = timing.future(mins=1)
        self.interval = config.get('pool', 'interval')
        log.debug("Initialised pool.  First process at %s",
                  timing.timestamp(self.next_process))

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

    def send(self):
        """Send messages from the Mixmaster Pool.
        """
        if timing.now() < self.next_process:
            return 0
        log.info("Beginning Pool processing.")
        # Set some static vars here so we don't repeatedly do it within the
        # following loop.
        poolpath = config.get('paths', 'pool')
        date = email.utils.formatdate()
        fromname = config.get('mail', 'address')
        for fn in self.pick_files():
            fq = os.path.join(poolpath, fn)
            f = open(fq, 'r')
            msg = email.message_from_file(f)
            f.close()
            msg['From'] = fromname
            msg['Date'] = date
            success = self.email.sendmail(msg)
            if send_success:
                log.debug("Deleting %s from pool", fn)
                os.remove(fq)
        # Return the time for the next pool processing.
        self.next_process = timing.dhms_future(self.interval)
        log.debug("Next pool process at %s",
                  timing.timestamp(self.next_process))


class ConfFiles():
    def __init__(self, filename, name):
        # mtime is set to the Modified date on the file in "since Epoch"
        # format.  Setting it to zero ensures the file is read on the first
        # pass.
        logname = "Pymaster.%s.%s" % (__name__, name)
        self.log = logging.getLogger(logname)
        mtime = 0
        self.mtime = mtime
        self.filename = filename

    def hit(self, testdata):
        if not os.path.isfile(self.filename):
            return False
        file_modified = os.path.getmtime(self.filename)
        if file_modified > self.mtime:
            (self.regex_rules,
             self.list_rules) = Utils.file2regex(self.filename)
            self.mtime = file_modified
        if testdata in self.list_rules:
            self.log.debug("Message matches: %s", testdata)
            return True
        if self.regex_rules:
            regex_test = self.regex_rules.search(testdata)
            if regex_test:
                self.log.debug("Message matches Regular Expression: %s",
                               regex_test.group(0))
                return True
        return False

pubring = KeyManager.Pubring()
if (__name__ == "__main__"):
    logfmt = config.get('logging', 'format')
    datefmt = config.get('logging', 'datefmt')
    log = logging.getLogger("Pymaster")
    log.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(fmt=logfmt, datefmt=datefmt))
    log.addHandler(handler)

    m = Mailbox()
    p = Pool()
    sleep = config.getint('general', 'interval')
    while True:
        m.process()
        p.send()
        log.info("Sleeping until %s",
                 timing.timestamp(timing.future(secs=sleep)))
        timing.sleep(sleep)
else:
    log = logging.getLogger("%s.Mail" % __name__)
