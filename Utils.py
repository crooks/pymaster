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

import Config
import Crypto.Random
import os.path

def capstring():
    """Return the remailer capstring.
    """
    caps = '$remailer{\"%s\"} = ' % config.get('general', 'shortname')
    caps += '\"<%s> mix' % config.get('mail', 'address')
    if config.getboolean('general', 'middleman'):
        caps += ' middle'
    if config.getint('pool', 'poolsize') >= 5:
        caps += ' reord'
    caps += ' klen%s' % config.getint('general', 'klen')
    caps += '\";'
    return caps

def poolfn(prefix):
    """Make up a suitably random filename for the pool entry.
    """
    while True:
        fn = prefix + Crypto.Random.get_random_bytes(8).encode("hex")
        fq = os.path.join(config.get('paths', 'pool'), fn)
        if not os.path.isfile(fq):
            break
    return fq

config = Config.Config().config
if (__name__ == "__main__"):
    print capstring()
    print poolfn('m')
