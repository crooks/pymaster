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
        # The following two variables define the time when the statfile was
        # last modified.
        self.exittime = 0
        self.nodetime = 0
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

    def get_exit(self):
        """Return a randomly selected exit remailer node.  The function also
           checks if the mlist2 file has been updated since it was last
           cached.  If it has been updated, the cache is repopulated using
           the file content.
        """
        if os.path.getmtime(self.mlist2) > self.exittime:
            log.debug("Repopulating exit remailer cache.")
            # Stats have been updated since we last cached them.
            exits = self.candidates(config.getint('chain', 'minlat'),
                                    config.getint('chain', 'maxlat'),
                                    config.getfloat('chain', 'relfinal'),
                                    exit=True)
            exitnum = len(exits)
            if exitnum == 0:
                raise ChainError("No candidate exit remailers")
            self.exits = exits
            self.exittime = os.path.getmtime(self.mlist2)
        exit = self.exits[self._randint(len(self.exits) - 1)]
        log.debug("Selected random exit: %s", exit)
        return exit

    def shuffle_nodes(self):
        """The Pycrypto shuffle function does an inline shuffle.  It probably
           wouldn't hurt to do that for our purposes but I prefer to copy the
           list, shuffle it and return the new list.
        """
        nodecopy = list(self.nodes)
        Crypto.Random.random.shuffle(nodecopy)
        return nodecopy

    def get_node(self):
        """As with get_exit but this function returns any candidate remailer,
           not just an exit node.
        """
        # TODO There is a slight danger that shuffle_nodes could be called
        # before this function has executed. This would be bad as self.nodes
        # wouldn't be populated at that time.  Currently this cannot happen
        # as the only call to shuffle_nodes is preceeded by a get_node call. 
        if os.path.getmtime(self.mlist2) > self.nodetime:
            log.debug("Repopulating remailer node cache.")
            # Stats have been updated since we last cached them.
            nodes = self.candidates(config.getint('chain', 'minlat'),
                                    config.getint('chain', 'maxlat'),
                                    config.getfloat('chain', 'relfinal'),
                                    exit=False)
            nodenum = len(nodes)
            if nodenum == 0:
                raise ChainError("No candidate remailers.")
            self.nodes = nodes
            self.nodetime = os.path.getmtime(self.mlist2)
        node = self.nodes[self._randint(len(self.nodes) - 1)]
        log.debug("Selected random node: %s", node)
        return node

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
        # Create a list of all known remailers.  This list is based on nodes
        # known in the Pubring as there's no point selecting nodes we cannot
        # encrypt messages to.
        remailers = self.pubring.get_names()
        # This loop validates that each of the remailers specified in the
        # chain do at least exist.
        for rem in chainlist:
            if rem is not "*" and rem not in remailers:
                raise ChainError("Unknown hardcoded remailer: %s" % rem)
        # Assign an exit node.  We do this first in order to ensure all the
        # exits don't get gobbled up as Middles.
        if chainlist[-1] == "*":
            chainlist[-1] = self.get_exit()
        if not "*" in chainlist:
            # We require no random Middleman Remailers so bail out before the
            # time consuming node selection process.
            return chainlist
        # Distance defines how close together within a chain the same node
        # can manifiest.
        distance = config.getint('chain', 'distance')
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
            # Quick option first.  Grab a random Middleman.
            new_node = self.get_node()
            if new_node in excludes:
                # Quick grab didn't work, the randomly selected node is in the
                # excluded nodes list.
                gotnode = False
                # Shuffle the list of Middleman Remailers and then test each
                # node in turn against the excluded nodes.  THe first node
                # that isn't excluded will be selected.
                nodes = self.shuffle_nodes()
                for new_node in nodes:
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
    log.setLevel(logging.WARN)
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(fmt=logfmt, datefmt=datefmt))
    log.addHandler(handler)
    import KeyManager
    import time
    pubring = KeyManager.Pubring()
    c = Chain(pubring)
    start = time.time()
    for n in range(500):
        c.chain("*, austria, *, *, *")
    end = time.time()
    print "Elapsed time: %s" % (end - start)
