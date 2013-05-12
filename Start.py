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
import email
import smtplib
from Config import config
import timing
import Mail
import DecodePacket
import EncodePacket
import KeyManager
import Utils


class Pool():
    def __init__(self, encode):
        self.next_process = timing.future(mins=1)
        self.interval = config.get('pool', 'interval')
        self.rate = config.getint('pool', 'rate')
        self.size = config.getint('pool', 'size')
        self.pooldir = config.get('paths', 'pool')
        # We need the packet encoder in order to generate dummy messages.
        self.encode = encode
        log.info("Initialised pool. Path=%s, Interval=%s, Rate=%s%%, "
                 "Size=%s.",
                 self.pooldir, self.interval, self.rate, self.size)
        log.debug("First pool process at %s",
                  timing.timestamp(self.next_process))

    def process(self):
        if timing.now() < self.next_process:
            return 0
        log.debug("Beginning Pool processing.")
        smtp = smtplib.SMTP(config.get('mail', 'server'))
        for fn in self.pick_files():
            if not fn.startswith('m'):
                # Currently all messages are prefixed with an m.
                continue
            fqfn = os.path.join(config.get('paths', 'pool'), fn)
            f = open(fqfn, 'r')
            msg = email.message_from_file(f)
            f.close()
            log.debug("Pool processing: %s", fn)
            if not 'To' in msg:
                log.warn("%s: Malformed pool message. No recipient "
                         "specified.", fn)
                continue
            msg["Message-ID"] = Utils.msgid()
            msg["Date"] = email.Utils.formatdate()
            msg["From"] = "%s <%s>" % (config.get('general', 'longname'),
                                       config.get('mail', 'address'))
            try:
                smtp.sendmail(msg["From"], msg["To"], msg.as_string())
                log.debug("Email sent to: %s", msg["To"])
            except smtplib.SMTPRecipientsRefused, e:
                log.warn("SMTP failed with: %s", e)
            self.delete(fqfn)
        smtp.quit()
        # Outbound dummy message generation.
        if random.randint(0, 100) < config.get('pool', 'outdummy'):
            log.debug("Generating dummy message.")
            self.encode.dummy()
        # Return the time for the next pool processing.
        self.next_process = timing.dhms_future(self.interval)
        log.debug("Next pool process at %s",
                  timing.timestamp(self.next_process))

    def delete(self, fqfn):
        """Delete files from the Mixmaster Pool."""
        os.remove(fqfn)
        log.debug("%s: Deleted", fqfn)

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
    loglevels = {'debug': logging.DEBUG, 'info': logging.INFO,
                 'warn': logging.WARN, 'error': logging.ERROR}
    log = logging.getLogger("Pymaster")
    log.setLevel(loglevels[config.get('logging', 'level')])
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(fmt=logfmt, datefmt=datefmt))
    log.addHandler(handler)

    pubring = KeyManager.Pubring()
    secring = KeyManager.Secring()
    encode = EncodePacket.Mixmaster(pubring)
    idlog = DecodePacket.IDLog()
    chunkmgr = DecodePacket.ChunkManager()
    mail = Mail.MailMessage(pubring, secring, idlog, encode, chunkmgr)
    pool = Pool(encode)
    sleep = timing.dhms_secs(config.get('general', 'interval'))
    while True:
        idlog.prune()
        chunkmgr.prune()
        mail.iterate_mailbox()
        pool.process()
        idlog.sync()
        chunkmgr.sync()
        log.debug("Sleeping for %s seconds", sleep)
        try:
            timing.sleep(sleep)
        except KeyboardInterrupt:
            idlog.close()
            chunkmgr.close()
            sys.exit(0)
