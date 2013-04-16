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

import os.path
import logging
import Crypto.Random.random
from Config import config


class ChainError(Exception):
    pass


class Chain():
    def __init__(self, pubring):
        mlist2 = config.get('keys', 'mlist2')
        if not os.path.isfile(mlist2):
            raise ChainError("%s: Stats file not found" % mlist2)
        self.mlist2 = mlist2
        self.shortname = config.get('general', 'shortname')
        self.pubring = pubring
        log.info("Chain handler initialised. Stats=%s", mlist2)

    def _striplist(self, l):
        """Take a list and return the same list with whitespace stripped from
        each element.
        """
        assert type(l) is list
        return ([x.strip() for x in l])

    def _randint(self, n):
        """Return a random Integer (0-255)
        """
        return int(Crypto.Random.random.randint(0, n))

    def candidates(self, minlat, maxlat, minup, exit=False):
        """Returns a list of remailer shortnames, where each remailer meets
        the latency, uptime and exit conditions requested.
        """

        f = open(self.mlist2, 'r')
        instats = False
        remailers = []
        shortnames = self.pubring.get_names()
        for line in f:
            if line.startswith("Generated: "):
                generated = line.split(": ", 1)[1].rstrip()
            elif line.startswith("----------"):
                instats = True
            elif instats and len(line.rstrip()) == 0:
                instats = False
            elif instats:
                name = line[0:13].rstrip()
                try:
                    lathrs = int(line[27:29].lstrip())
                except ValueError:
                    lathrs = 0
                latmin = int(line[30:32])
                latency = (lathrs * 60) + latmin
                if latency < minlat or latency > maxlat:
                    continue
                uptime = float(line[49:54].lstrip())
                if uptime < minup:
                    continue
                opts = line[57:72]
                if exit and 'D' in opts:
                    continue
                # This check ensures there is a public key corresponding to
                # the candidate.  If not, we can't encrypt to it.
                if name in shortnames:
                    remailers.append(name)
                else:
                    log.warn("%s: In stats but no Public Key available.", name)
        f.close()
        return remailers

    def randexit(self):
        """Select a random exit node.  This is used in Chain construction and
        also, when Randhopping, to select the Randhop node.
        """
        exits = self.candidates(config.getint('chain', 'minlat'),
                                config.getint('chain', 'maxlat'),
                                config.getfloat('chain', 'relfinal'),
                                exit=True)
        exitnum = len(exits)
        if exitnum == 0:
            raise ChainError("No candidate Exit Remailers")
        exit = exits[self._randint(exitnum - 1)]
        log.debug("Selected random exit: %s", exit)
        return exit

    def randany(self):
        """Like randexit but pick any random node, not just exits.
        """
        remailers = self.candidates(0, 5999, 0)
        # Remove the local remailer from the list.  On no occasions
        # do we want to randomly select the local node.
        if self.shortname in remailers:
            remailers.remove(self.shortname)
        remcount = len(remailers)
        if remcount == 0:
            raise ChainError("No candidate remailers")
        remailer = remailers[self._randint(remcount - 1)]
        log.debug("Select random node: %s", remailer)
        return remailer

    def chain(self, chainstr=None):
        if chainstr is None:
            # Use the configured default Chain
            chainstr = config.get('chain', 'default')
        # Create a list of chain elements and strip whitespace
        chainlist = self._striplist(chainstr.split(","))
        chainnum = len(chainlist)
        if chainnum > 20:
            # Mixmaster only deals with chains of up to 20 Remailers
            raise ChainError("Max Chain length exceeded")
        # Create a list of all known remailers
        remailers = self.candidates(0, 5999, 0)
        # This loop validates that each of the remailers specified in the
        # chain do at least exist.
        for rem in chainlist:
            if rem is not "*" and rem not in remailers:
                raise ChainError("%s: Unknown hardcoded remailer" % rem)
        # Assign an exit node.  We do this first in order to ensure all the
        # exits don't get gobbled up as Middles.
        if chainlist[-1] == "*":
            chainlist[-1] = self.randexit()
        if not "*" in chainlist:
            # We require no random Middleman Remailers so bail out before the
            # time consuming node selection process.
            return chainlist
        # Distance defines how close together within a chain the same node
        # can manifiest.
        distance = config.getint('chain', 'distance')
        # Middleman candidates
        middles = self.candidates(config.getint('chain', 'minlat'),
                                  config.getint('chain', 'maxlat'),
                                  config.getfloat('chain', 'minrel'))
        midnum = len(middles)
        if midnum == 0:
            raise ChainError("No candidate Middleman Remailers")
        # Iterate over the element numbers within the chain.
        for n in range(chainnum):
            if chainlist[n] != "*":
                # Ignore hardcoded remailers
                continue
            # Create a list of nodes that are excluded by distance rules
            exclude_lower = n - distance
            exclude_upper = n + distance + 1
            if exclude_lower < 0:
                exclude_lower = 0
            if exclude_upper > chainnum:
                exclude_upper = chainnum
            excludes = chainlist[exclude_lower:exclude_upper]
            # Quick option first.  Grab a random Middleman
            new_node = middles[self._randint(midnum - 1)]
            if new_node in excludes:
                # Quick grab didn't work, the randomly selected node is in the
                # excluded nodes list.
                gotnode = False
                # Shuffle the list of Middleman Remailers and then test each
                # node in turn against the excluded nodes.  THe first node
                # that isn't excluded will be selected.
                Crypto.Random.random.shuffle(middles)
                for new_node in middles:
                    if new_node not in excludes:
                        gotnode = True
                        break
                if not gotnode:
                    # Every candidate Middleman is excluded.
                    raise ChainError("Infufficient remailer pool")
            chainlist[n] = new_node
        log.debug("Created chain: %s", chainlist)
        return chainlist


log = logging.getLogger("Pymaster.%s" % __name__)
if (__name__ == "__main__"):
    logfmt = config.get('logging', 'format')
    datefmt = config.get('logging', 'datefmt')
    log = logging.getLogger("Pymaster")
    log.setLevel(logging.DEBUG)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(fmt=logfmt, datefmt=datefmt))
    log.addHandler(handler)
    import KeyManager
    pubring = KeyManager.Pubring()
    c = Chain(pubring)
    print c.chain("*, austria, *, *, *")
    print "Random Node: %s" % c.randany()
    print "Random Exit: %s" % c.randexit()
