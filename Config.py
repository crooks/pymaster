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

def mkdir(directory):
    if not os.path.isdir(directory):
        os.mkdir(directory, 0700)
        sys.stdout.write("Created directory %s\n" % directory)

def makepath(basedir, subdir, val):
    if config.has_option('paths', val):
        path = config.get('paths', val)
    else:
        path = os.path.join(basedir, subdir)
        config.set('paths', subdir, path)
    mkdir(path)
    return path

def makeopt(sect, opt, val):
    if not config.has_option(sect, opt):
        config.set(sect, opt, val)


# Configure the Config Parser.
config = ConfigParser.RawConfigParser()

# By default, all the paths are subdirectories of the homedir.
homedir = os.path.expanduser('~')

config.add_section('general')
config.set('general', 'shortname', 'pymaster')
config.set('general', 'longname', 'Pymaster Remailer')
config.set('general', 'loglevel', 'info')
config.set('general', 'middleman', 0)
config.set('general', 'klen', 128)
config.set('general', 'interval', 60)
config.set('general', 'passphrase', 'A badly configured server')
config.set('general', 'block_first', 1)

config.add_section('logging')
config.set('logging', 'level', 'debug')
config.set('logging', 'format', '%(asctime)s %(name)s %(levelname)s %(message)s')
config.set('logging', 'datefmt', '%Y-%m-%d %H:%M:%S')
config.set('logging', 'retain', 7)

config.add_section('chain')
config.set('chain', 'minlat', 20)
config.set('chain', 'maxlat', 120)
config.set('chain', 'minrel', 80)
config.set('chain', 'relfinal', 95)
config.set('chain', 'distance', 2)
config.set('chain', 'default', '*,*,*')

config.add_section('pool')
config.set('pool', 'size', 45)
config.set('pool', 'rate', 65)
config.set('pool', 'indummy', 10)
config.set('pool', 'outdummy', 90)
config.set('pool', 'interval', '15m')

config.add_section('mail')
config.set('mail', 'server', 'localhost')
config.set('mail', 'domain', 'here.invalid')
config.set('mail', 'address', 'pymaster@domain.invalid')
config.set('mail', 'outbound_address', 'noreply@here.invalid')
config.set('mail', 'interval', '15m')

# Try and process the .aam2mailrc file.  If it doesn't exist, we
# bailout as some options are compulsory.
#if options.rc:
#    configfile = options.rc
if 'PYMASTER' in os.environ:
    configfile = os.environ['PYMASTER']
else:
    configfile = os.path.join(homedir, '.pymasterrc')

if not config.has_option('mail', 'mid'):
    middomain = config.get('mail', 'address').split('@', 1)[1]
    config.set('mail', 'mid', middomain)

config.add_section('paths')
if not WRITE_DEFAULT_CONFIG and os.path.isfile(configfile):
    config.read(configfile)

# We have to set basedir _after_ reading the config file because
# other paths need to default to subpaths of it.
basedir = makepath(homedir, 'pymaster', 'basedir')
# Keyring path.  Default: ~/pymaster/keyring
config.add_section('keys')
keypath = makepath(basedir, 'keyring', 'keyring')
makeopt('keys', 'secring', os.path.join(keypath, 'secring.mix'))
makeopt('keys', 'pubring', os.path.join(keypath, 'pubring.mix'))
makeopt('keys', 'pubkey', os.path.join(keypath, 'key.txt'))
makeopt('keys', 'mlist2', os.path.join(keypath, 'mlist2.txt'))
config.set('keys', 'validity_days', 372)
config.set('keys', 'grace_days', 28)
# Logging Directory
logpath = makepath(basedir, 'log', 'log')
# Mixmaster Pool
poolpath = makepath(basedir, 'pool', 'pool')
# Email options
mailpath = makepath(basedir, 'Maildir', 'maildir')
mkdir(os.path.join(mailpath, 'cur'))
mkdir(os.path.join(mailpath, 'new'))
mkdir(os.path.join(mailpath, 'tmp'))
config.add_section('etc')
etcpath = makepath(basedir, 'etc', 'etc')
makeopt('etc', 'dest_alw', os.path.join(etcpath, 'dest.alw'))
makeopt('etc', 'dest_blk', os.path.join(etcpath, 'dest.blk'))
libpath = makepath(basedir, 'lib', 'lib')
makeopt('general', 'idlog', os.path.join(libpath, 'idlog.db'))

if WRITE_DEFAULT_CONFIG:
    with open('config.sample', 'wb') as configfile:
        config.write(configfile)
# Setting this last prevents it being overridden in the config file.
# Hardly security but it doesn't really matter.
config.set('general', 'version', '0.1a.pymaster')
