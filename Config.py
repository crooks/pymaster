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


WRITE_DEFAULT_CONFIG = False
USE_BASEDIR = True


def mkdir(directory):
    if not WRITE_DEFAULT_CONFIG and not os.path.isdir(directory):
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


def str_tidy(instr):
    """Take a string and return it with each word lowercase and an uppercase
       first letter.
    """
    inwords = instr.split(" ")
    outwords = []
    for word in inwords:
        outwords.append(word[0].upper() + word[1:].lower())
    return ' '.join(outwords)


# Configure the Config Parser.
config = ConfigParser.RawConfigParser()


config.add_section('general')
config.set('general', 'loglevel', 'info')
config.set('general', 'middleman', 0)
config.set('general', 'klen', 128)
config.set('general', 'interval', '5m')
config.set('general', 'idexp', 7)
config.set('general', 'packetexp', 7)
#config.set('general', 'passphrase', 'A badly configured server')
config.set('general', 'block_first', 1)

config.add_section('logging')
config.set('logging', 'level', 'info')
config.set('logging', 'format',
           '%(asctime)s %(name)s %(levelname)s %(message)s')
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

config.add_section('paths')

if WRITE_DEFAULT_CONFIG:
    sys.stdout.write("WARNING: Configuration dictates WRITE_DEFAULT_CONFIG. "
                     "Based on this, no attempt will be made to read the "
                     "user-defined config file or create any required "
                     "directories.\n")
    config.set('general', 'shortname', 'pymaster')
    config.set('general', 'longname', 'Pymaster Remailer')
    config.set('mail', 'address', 'mixmaster@domain.invalid')
    config.set('general', 'passphrase', 'swordfish')
    config.set('mail', 'outbound_address', 'noreply@domain.invalid')
    # By default, all the paths are subdirectories of the homedir.
    if USE_BASEDIR:
        homedir = "/homedir"
        basedir = os.path.join(homedir, "basedir")
    else:
        basedir = "/homedir"
else:
    homedir = os.path.expanduser('~')
    # Try and process the .pymasterrc file.  If it doesn't exist, we
    # bailout as some options are compulsory.
    #if options.rc:
    #    configfile = options.rc
    if 'PYMASTER' in os.environ:
        configfile = os.environ['PYMASTER']
    else:
        configfile = os.path.join(homedir, '.pymasterrc')
    if os.path.isfile(configfile):
        config.read(configfile)

    else:
        sys.stdout.write("No configuration file found.  The expected "
                         "location is %s.  This can be overridden by defining "
                         "the PYMASTER Environment Variable.\n" % configfile)
        sys.exit(1)
    # We have to set basedir _after_ reading the config file because
    # other paths need to default to subpaths of it.
    if USE_BASEDIR:
        basedir = makepath(homedir, 'pymaster', 'basedir')
    else:
        config.set('paths', 'basedir', homedir)
        mkpath(config.get('paths', 'basedir'))

# Here we check that compulsory options with no defaults have been
# user-defined.  In some cases, we can make assumptions based on other
# prequisite answers, in other cases we raise an error.
if not config.has_option('general', 'shortname'):
    sys.stdout.write("ERROR: Configuration does not define a shortname for "
                     "the remailer.  This is the name that will be "
                     "advertised on the Public Key and in Stats.\n")
    sys.exit(1)
if not config.has_option('general', 'longname'):
    remname = str_tidy(config.get('general', 'shortname'))
    config.set('general', 'longname', '%s Remailer' % remname)
    sys.stdout.write("WARNING: No remailer longname defined.  Based on the "
                     "configured shortname, the following is assumed: %s\n"
                     % config.get('general', 'longname'))
if not config.has_option('general', 'passphrase'):
    sys.stdout.write("ERROR: The configuration does not define a passphrase "
                     "for the remailer.  This passphrase is used to encrypt "
                     "the Secret Key written to disk.\n")
    sys.exit(1)
if not config.has_option('mail', 'address'):
    sys.stdout.write("ERROR: Configuration does not define an email address "
                     "for the remailer.  This is the address that will be "
                     "advertised on the remailer's Public Key.\n")
    sys.exit(1)
# By splitting the email address into domain and local, we can make some
# assumptions for other options.
local, domain = config.get('mail', 'address').split("@", 1)
if not config.has_option('mail', 'outbound_address'):
    config.set('mail', 'outbound_address', 'noreply@%s' % domain)
    sys.stdout.write("WARNING: Configuration does not define an outbound "
                     "email address.  This is the From address used on "
                     "messages sent from the remailer.  Based on the defined "
                     "email address, the following is assumed: %s\n"
                     % config.get('mail', 'outbound_address'))
makeopt('mail', 'mid', domain)

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
makeopt('etc', 'head_alw', os.path.join(etcpath, 'head.alw'))
makeopt('etc', 'head_blk', os.path.join(etcpath, 'head.blk'))
makeopt('etc', 'helpfile', os.path.join(etcpath, 'help.txt'))
makeopt('etc', 'adminkey', os.path.join(etcpath, 'adminkey.txt'))
libpath = makepath(basedir, 'lib', 'lib')
makeopt('general', 'idlog', os.path.join(libpath, 'idlog.db'))

if WRITE_DEFAULT_CONFIG:
    with open('config.sample', 'w') as configfile:
        config.write(configfile)
# Setting this last prevents it being overridden in the config file.
# Hardly security but it doesn't really matter.
config.set('general', 'version', '0.1a.pymaster')
