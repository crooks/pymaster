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

from Config import config
import Crypto.Random
import os.path
import timing
import logging
import re


def capstring():
    """Return the remailer capstring.
    """
    caps = '$remailer{\"%s\"} = ' % config.get('general', 'shortname')
    caps += '\"<%s> mix' % config.get('mail', 'address')
    if config.getboolean('general', 'middleman'):
        caps += ' middle'
    if config.getint('pool', 'size') >= 5:
        caps += ' reord'
    if config.has_option('general', 'extflags'):
        caps += ' %s' % config.get('general', 'extflags')
    caps += ' klen%s' % config.getint('general', 'klen')
    caps += '\";'
    return caps


def pool_filename(prefix):
    """Make up a suitably random filename for the pool entry.
    """
    while True:
        fn = prefix + Crypto.Random.get_random_bytes(8).encode("hex")
        fq = os.path.join(config.get('paths', 'pool'), fn)
        if not os.path.isfile(fq):
            break
    return fq


def msgid():
    return "<%s.%s@%s>" % (timing.msgidstamp(),
                           Crypto.Random.get_random_bytes(4).encode("hex"),
                           config.get('mail', 'mid'))


def file2regex(filename):
    """Read a given file and return a list of items and, if regex formatted, a
    compiled Regular Expression.

    """

    reglines = []
    listlines = []
    for line in file2list(filename):
        if line.startswith("/") and line.endswith("/"):
            reglines.append(line[1:-1])
        else:
            listlines.append(line)
    if len(reglines) == 0:
        # No valid regex entires exist in the file.
        compiled = False
    else:
        regex = '|'.join(reglines)
        # This should never happen but best to check as || will match
        # everything.
        regex = regex.replace('||', '|')
        compiled = re.compile(regex)
    return compiled, listlines


def file2list(filename):
    if not os.path.isfile(filename):
        print "%s: File not found" % filename
        return []
    valid = []
    f = open(filename, 'r')
    for line in f:
        # Strip comments (including inline)
        content = line.split('#', 1)[0].strip()
        # Ignore empty lines
        if len(content) > 0:
            valid.append(content)
    f.close()
    return valid


if (__name__ == "__main__"):
    logfmt = config.get('logging', 'format')
    datefmt = config.get('logging', 'datefmt')
    log = logging.getLogger("Pymaster")
    log.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(fmt=logfmt, datefmt=datefmt))
    log.addHandler(handler)

    print capstring()
    print poolfn('m')
    print msgid()
    destalw = ConfFiles(config.get('etc', 'dest_alw'), 'dest_alw')
    print dir(destalw)
    print destalw.hit('steve@mixmin.net')
