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
import email
import smtplib
from Crypto.Hash import MD5
import Config
import Utils


class MessageError(Exception):
    pass


class Mailbox():
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

        mixmes = False
        # It's a reasonable assumption that headers are at the top of a mail
        # message.
        inhead = True
        subject = None
        msgfrom = None
        f = self.inbox.get_file(key)
        for line in f:
            if line.startswith("From: "):
                msgfrom = line.split(": ", 1)[1].strip().lower()
            elif line.startswith("Subject: "):
                subject = line.split(": ", 1)[1].strip().lower()
            elif line == "\n":
                if (subject == 'remailer-key' and
                    msgfrom is not None):
                    send_remailer_key(msgfrom)
                    break
                inhead = False
            elif inhead:
                # Go no further than this until we're not handling headers.
                continue
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
        f.close()
        if mixmes:
            packet = packet.decode("base64")
            # Validate the length and digest of the packet.
            if length != len(packet):
                raise MessageError("Incorrect packet Length")
            if digest != MD5.new(data=packet).digest():
                raise MessageError("Mixmaster message digest failed")
            self.header = packet[0:512]
            self.headers = packet[512:10240]
            self.body = packet[10240:]
        return mixmes


def send_remailer_key(recipient):
    #smtp = smtplib.SMTP(config.get('mail', 'server'))
    payload = '%s\n\n' % Utils.capstring()
    payload += 'Here is the Mixmaster key:\n\n'
    payload += '=-=-=-=-=-=-=-=-=-=-=-=\n'
    f = open(config.get('keys', 'pubkey'), 'r')
    payload += f.read()
    f.close()
    msg = email.message_from_string(payload)
    msg["From"] = "%s <%s>" % (config.get('general', 'longname'),
                               config.get('mail', 'address'))
    msg["Subject"] = "Remailer key for %s" % config.get('general',
                                                        'shortname')
    msg['Date'] = email.utils.formatdate()
    msg['To'] = recipient
    #smtp.sendmail(msg["From"], msg["To"], msg.as_string())

config = Config.Config().config
if (__name__ == "__main__"):
    m = Mailbox()
    for msg in m.messages():
        try:
            m.read_message(msg)
        except MessageError, e:
            pass
            #print "Exception: %s" % e
