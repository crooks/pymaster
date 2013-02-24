#!/usr/bin/python
#
# vim: tabstop=4 expandtab shiftwidth=4 noautoindent
#
# pymaster.py - A Python version of the Mixmaster Remailer
#
# Copyright (C) 2013 Steve Crook <steve@mixmin.net>
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

import ConfigParser
from optparse import OptionParser
import os
import sys
import timing
import re

WRITE_DEFAULT_CONFIG = False


class Config():
    def __init__(self):
        # Configure the Config Parser.
        self.config = ConfigParser.RawConfigParser()
        self.make_config()

    def mkdir(self, directory):
        if not os.path.isdir(directory):
            os.mkdir(directory, 0700)
            sys.stdout.write("Created directory %s\n" % directory)

    def makepath(self, basedir, subdir, val):
        if self.config.has_option('paths', val):
            path = self.config.get('paths', val)
        else:
            path = os.path.join(basedir, subdir)
            self.config.set('paths', subdir, path)
        self.mkdir(path)
        return path

    def makeopt(self, sect, opt, val):
        if not self.config.has_option(sect, opt):
            self.config.set(sect, opt, val)

    def make_config(self):
        # By default, all the paths are subdirectories of the homedir.
        homedir = os.path.expanduser('~')

        self.config.add_section('general')
        self.config.set('general', 'loglevel', 'info')
        self.config.set('general', 'middleman', 0)

        self.config.add_section('chain')
        self.config.set('chain', 'minlat', 20)
        self.config.set('chain', 'maxlat', 120)
        self.config.set('chain', 'minrel', 80)
        self.config.set('chain', 'relfinal', 95)
        self.config.set('chain', 'distance', 2)
        self.config.set('chain', 'default', '*,*,*')

        self.config.add_section('mail')
        self.config.set('mail', 'server', 'localhost')
        self.config.set('mail', 'domain', 'here.invalid')
        self.config.set('mail', 'outbound_address', 'noreply@here.invalid')

        # Try and process the .aam2mailrc file.  If it doesn't exist, we
        # bailout as some options are compulsory.
        if options.rc:
            configfile = options.rc
        elif 'PYMASTER' in os.environ:
            configfile = os.environ['PYMASTER']
        else:
            configfile = os.path.join(homedir, '.pymasterrc')

        self.config.add_section('paths')
        if not WRITE_DEFAULT_CONFIG and os.path.isfile(configfile):
            self.config.read(configfile)

        # We have to set basedir _after_ reading the config file because
        # other paths need to default to subpaths of it.
        basedir = self.makepath(homedir, 'pymaster', 'basedir')
        # Keyring path.  Default: ~/pymaster/keyring
        self.config.add_section('keys')
        keypath = self.makepath(basedir, 'keyring', 'keyring')
        self.makeopt('keys', 'seckey', os.path.join(keypath, 'seckey.pem'))
        self.makeopt('keys', 'pubring', os.path.join(keypath, 'pubring.mix'))
        self.makeopt('keys', 'mlist2', os.path.join(keypath, 'mlist2.txt'))
        # Email options
        mailpath = self.makepath(basedir, 'Maildir', 'maildir')
        self.mkdir(os.path.join(mailpath, 'cur'))
        self.mkdir(os.path.join(mailpath, 'new'))
        self.mkdir(os.path.join(mailpath, 'tmp'))
        self.config.add_section('etc')
        etcpath = self.makepath(basedir, 'etc', 'etc')
        self.makeopt('etc', 'dest_alw', os.path.join(etcpath, 'dest.alw'))
        self.makeopt('etc', 'dest_blk', os.path.join(etcpath, 'dest.blk'))

        if WRITE_DEFAULT_CONFIG:
            with open('config.sample', 'wb') as configfile:
                self.config.write(configfile)


class Parser():
    def __init__(self, fn):
        assert type(fn) is str
        self.fn = fn
        self._reload()

    def _reload(self):
        self.regex, self.text = file2regex(self.fn)
        self.reload_time = timing.future(hours=1)

    def validate(self, candidates, allhits=True):
        """If allhits is True, validate that all the candidates in a given list
        match at least one of the conditions stated.  If allhists is False then
        validate that *any* of the candidates match a condition.
        """

        # struct.unpack returns a tuple
        assert type(candidates) is tuple
        # Check if it's time to reload the config file.
        if timing.now() > self.reload_time:
            self._reload()
        # Returns True when all candidates match a condition.
        allhit = False
        # Returns True if any candidate matchs a condition.
        onehit = False
        hits = 0
        for c in candidates:
            cc = c.rstrip('\x00')
            if self.regex and self.regex.search(cc):
                hits += 1
            elif self.text and cc in self.text:
                hits += 1
        if allhits:
            return len(candidates) == hits
        else:
            return hits > 0


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
        # No valid entires exist in the file.
        print '%s: No valid entries found' % filename
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

# OptParse comes first as ConfigParser depends on it to override the path to
# the config file.
parser = OptionParser()

parser.add_option("--config", dest="rc",
                      help="Override PyMaster config file location")
parser.add_option("--start", dest="start", action="store_true",
                      help="Start the aam2mail daemon")
parser.add_option("--stop", dest="stop", action="store_true",
                      help="Stop the aam2mail daemon")
parser.add_option("--restart", dest="restart", action="store_true",
                      help="Restart the aam2mail daemon")

(options, args) = parser.parse_args()
