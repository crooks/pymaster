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
from Config import config
import timing
import Mail
import Pool
import DecodePacket
import EncodePacket
import KeyManager


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
    pool = Pool.Pool(encode)
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
