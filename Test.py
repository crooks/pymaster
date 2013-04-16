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
import timing
import DecodePacket
import EncodePacket
import KeyManager
import Utils
from Config import config

logfmt = config.get('logging', 'format')
datefmt = config.get('logging', 'datefmt')
log = logging.getLogger("Pymaster")
log.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter(fmt=logfmt, datefmt=datefmt))
log.addHandler(handler)

pubring = KeyManager.Pubring()
secring = KeyManager.Secring()
mixmail = DecodePacket.MixMail()
mixpacket = DecodePacket.MixPacket()
idlog = DecodePacket.IDLog()
decode = DecodePacket.Mixmaster(secring, idlog)
encode = EncodePacket.Mixmaster(pubring)

msg = email.message.Message()
msg['Dests'] = 'test@test.invalid'
msg['Cc'] = 'mail2news@mixmin.net'
msg['Newsgroups'] = 'news.group'
msg.set_payload("Test Message")
payload = EncodePacket.Payload(msg)
payload.email2payload()
inmsg = encode.makemsg(payload, chainstr='pymaster,pymaster,pymaster')
ismix = mixmail.email2packet(inmsg)
if ismix:
    packet = mixmail.get_packet()
    mixpacket.unpack(packet)
    outmsg = decode.process(mixpacket)
else:
    print "Not an intermediate message"
ismix = mixmail.email2packet(outmsg)
if ismix:
    packet = mixmail.get_packet()
    mixpacket.unpack(packet)
    outmsg = decode.process(mixpacket)
else:
    print "Not an intermediate message"
ismix = mixmail.email2packet(outmsg)
if ismix:
    packet = mixmail.get_packet()
    mixpacket.unpack(packet)
    outmsg = decode.process(mixpacket)
    print outmsg.as_string()
else:
    print "Not an exit Mixmaster message"
