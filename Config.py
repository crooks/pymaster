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

def mkdir(directory):
    if not os.path.isdir(directory):
        os.mkdir(directory, 0700)
        sys.stdout.write("Created directory %s\n" % directory)

def make_config():
    # Configure the Config Parser.
    config = ConfigParser.RawConfigParser()

    # By default, all the paths are subdirectories of the homedir.
    homedir = os.path.expanduser('~')

    config.add_section('general')
    config.set('general', 'loglevel', 'info')

    config.add_section('mail')
    config.set('mail', 'maildir', os.path.join(homedir, 'Maildir'))
    config.set('mail', 'server', 'localhost')
    config.set('mail', 'domain', 'here.invalid')
    config.set('mail', 'outbound_address', 'noreply@here.invalid')

    # Try and process the .aam2mailrc file.  If it doesn't exist, we bailout
    # as some options are compulsory.
    if options.rc:
        configfile = options.rc
    elif 'PYMASTER' in os.environ:
        configfile = os.environ['PYMASTER']
    else:
        configfile = os.path.join(homedir, '.pymasterrc')

    config.add_section("paths")
    if not WRITE_DEFAULT_CONFIG and os.path.isfile(configfile):
        config.read(configfile)

    # We have to set basedir _after_ reading the config file because
    # other paths need to default to subpaths of it.
    if config.has_option('paths', 'basedir'):
        basedir = config.get('paths', 'basedir')
    else:
        basedir = os.path.join(homedir, 'pymaster')
        config.set('paths', 'basedir', basedir)
    mkdir(config.get('paths', 'basedir'))

    if WRITE_DEFAULT_CONFIG:
        with open('config.sample', 'wb') as configfile:
            config.write(configfile)

    return config


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
config = make_config()
