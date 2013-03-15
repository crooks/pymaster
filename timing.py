#!/usr/bin/python
#
# vim: tabstop=4 expandtab shiftwidth=4 autoindent
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
# This file forms the start on some work to allow newsgroup filters to be
# added and auto-expired after a defined period.

import datetime
import time


def future(days=0, hours=0, mins=0, secs=0):
    return now() + datetime.timedelta(days=days, hours=hours,
                                      minutes=mins, seconds=secs)

def dhms_future(timestr):
    """Take a string formatted as 00h and convert it to a time in the future.
    """
    period = int(timestr[0:-1])
    unit = timestr[-1].lower()
    if unit == "d":
        return future(days=period)
    elif unit == "h":
        return future(hours=period)
    elif unit == "m":
        return future(mins=period)
    elif unit == "s":
        return future(secs=period)
    raise ValueError("%s: Unknown time period char" % unit)


def daydelta(dateobj, days):
    return dateobj + datetime.timedelta(days=days)


def timestamp(stamp):
    return stamp.strftime("%Y-%m-%d %H:%M:%S")


def msgidstamp():
    return now().strftime("%Y%m%d%H%M%S")


def datestamp(stamp):
    return stamp.strftime("%Y-%m-%d")


def dateobj(datestr):
    """Take a string formated date (yyyy-mm-dd) and return a datetime
    object.
    """
    return datetime.datetime.strptime(datestr, '%Y-%m-%d')


def now():
    return datetime.datetime.utcnow()
    #return datetime.datetime.now()


def nowstamp():
    """A shortcut function to return a textual representation of now."""
    return timestamp(now())


def today():
    """Return a string representation of today's date."""
    return datestamp(now())


def last_midnight():
    return now().replace(hour=0, minute=0, second=0, microsecond=0)


def next_midnight():
    """Return a datetime object relating to the next midnight.

    """
    return last_midnight() + datetime.timedelta(days=1)

def sleep(n):
    time.sleep(n)

if (__name__ == "__main__"):
    print timestamp(future(hours=1))
    print nowstamp()
    print last_midnight()
    print next_midnight()
    print timestamp(dhms_future("15m"))
