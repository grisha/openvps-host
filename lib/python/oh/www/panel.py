#
# Copyright 2004 OpenHosting, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# $Id: panel.py,v 1.1 2004/03/25 16:48:40 grisha Exp $

""" This is a primitive handler that should
    display usage statistics. This requires mod_python
    3.1 or later.
    """

# XXX The code below is ugly and needs to be rewritten

import os
import time

from mod_python import apache

from oh.common import rrdutil
from oh.host import cfg

MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
          'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

GB = 1073741824.0  # bytes in gigabyte

def handler(req):

    # figure out the vserver name
    path = os.path.normpath(req.uri)
    name = path.split('/')[1]

    last = path.split('/')[-1]
    if last == 'day_graph':
        return day_graph(req, name)
    if last == 'month_graph':
        return month_graph(req, name)
    if last == 'quarter_graph':
        return quarter_graph(req, name)

    # location of the bandwidth rrd
    rrd = os.path.join(cfg.VAR_DB_OH, '%s.rrd' % name)

    data = []

    yyyy, mm = time.localtime()[0:2]
    i, o  = rrdutil.month_total(rrd, yyyy, mm)
    data.append([yyyy, MONTHS[mm-1], i, o])

    yyyy, mm = rrdutil.prev_month(yyyy, mm)
    i, o = rrdutil.month_total(rrd, yyyy, mm)
    data.append([yyyy, MONTHS[mm-1], i, o])

    yyyy, mm = rrdutil.prev_month(yyyy, mm)
    i, o = rrdutil.month_total(rrd, yyyy, mm)
    data.append([yyyy, MONTHS[mm-1], i, o])

    req.content_type = 'text/html'

    req.write('<html>\n')
#    req.write('<link rel="STYLESHEET" type="text/css" '
#              'href="http://www.openhosting.com/styles/style.css">\n')
    req.write('<center>\n')
    req.write('<h1>Bandwidth use on server <em>%s</em></h1>\n' % name)
    req.write('<h3>%s</h3>\n' % time.ctime())
    req.write('<table border=1 cellpadding=5>\n')
    req.write('<tr><th></th><th>Input</th><th>Output</th><th>Total</th></tr>\n')
    for d in data:
        req.write('<tr><th>%s %d</th>'
                  '<td><b>%.2f Gb</b> (%d bytes)</td>'
                  '<td><b>%.2f Gb</b> (%d bytes)</td>'
                  '<td><b>%.2f Gb</b> (%d bytes)</td></tr>\n' %
                  (d[1], d[0], d[2]/GB, d[2], d[3]/GB, d[3], (d[2]+d[3])/GB, d[2]+d[3]))
    req.write('</table><br>\n')
    req.write('<em>(1 gigabyte is 1073741824 bytes)</em>\n')
    req.write('<h3>Throughput statistics</h3>\n')
    req.write('<img src="day_graph"><br><br>\n')
    req.write('<img src="month_graph"><br><br>\n')
    req.write('<img src="quarter_graph"><br><br>\n')
    req.write('<em>(Note - the above graphs represent number of bits transerred per second. '
              'One byte is equivalent to eight bits.)</em><br><br>\n')
    req.write('<hr><em>Copyright 2004 OpenHosting, Inc.</em>\n')
    req.write('</center>\n')
    req.write('</html>')

    return apache.OK

def day_graph(req, name):

    # location of the bandwidth rrd
    rrd = os.path.join(cfg.VAR_DB_OH, '%s.rrd' % name)

    image = rrdutil.graph(rrd, back=86400, title='Last 24 hours')

    req.content_type = 'image/gif'
    req.sendfile(image)
    os.unlink(image)

    return apache.OK

def month_graph(req, name):

    # location of the bandwidth rrd
    rrd = os.path.join(cfg.VAR_DB_OH, '%s.rrd' % name)

    image = rrdutil.graph(rrd, back=2592000, title='Last 30 days')

    req.content_type = 'image/gif'
    req.sendfile(image)
    os.unlink(image)

    return apache.OK

def quarter_graph(req, name):

    # location of the bandwidth rrd
    rrd = os.path.join(cfg.VAR_DB_OH, '%s.rrd' % name)

    image = rrdutil.graph(rrd, back=7614000, title='Last 90 days')

    req.content_type = 'image/gif'
    req.sendfile(image)
    os.unlink(image)

    return apache.OK
