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
import mailbox
from Crypto.Hash import MD5
import Config


class MessageError(Exception):
    pass

class Payload():
    pass


class Message():
    def __init__(self):
        self.inbox = mailbox.Maildir(config.get('paths', 'maildir'),
                                     factory=None, create=False)

    def messages(self):
        # Iterate over each message in the inbox.  This loop effectively
        # envelops all processing.
        return self.inbox.iterkeys()


    def read_message(self, key):
        """-----BEGIN REMAILER MESSAGE-----
           [packet length ]
           [message digest]
           [encoded packet]
           -----END REMAILER MESSAGE-----
        """

        msgtxt = self.inbox.get_string(key)
        p = Payload()
        mixmes = False
        for line in msgtxt.split("\n"):
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
        if not mixmes:
            # There is no Begin Cutmark in the message.  Not an issue.  Just
            # means this isn't a Mixmaster message.
            raise MessageError("EOF without Begin Cutmark.")
        packet = packet.decode("base64")
        # Validate the length and digest of the packet.
        if length != len(packet):
            raise MessageError("Incorrect packet Length")
        if digest != MD5.new(data=packet).digest():
            raise MessageError("Mixmaster message digest failed")
        p.header = packet[0:512]
        p.headers = packet[512:10240]
        p.body = packet[10240:]
        return p

config = Config.Config().config
if (__name__ == "__main__"):
    m = Message()
    for k in m.messages():
        try:
            payloadobj = m.read_message(k)
        except MessageError, e:
            print "%s: Message Error (%s)" % (k, e)
        print len(payloadobj.header)
