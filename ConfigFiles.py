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

import re
import timing
import os.path

class FileParser():
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

        assert type(candidates) is list
        # Check if it's time to reload the config file.
        if timing.now() > self.reload_time:
            self._reload()
        # Returns True when all candidates match a condition.
        allhit = False
        # Returns True if any candidate matchs a condition.
        onehit = False
        hits = 0
        for c in candidates:
            if self.regex and self.regex.search(c):
                hits += 1
            elif self.text and c in self.text:
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

if (__name__ == "__main__"):
    alw = FileParser('dest.alw')
    addylist = ['steve@mixmin.net']
    print alw.validate(addylist)
