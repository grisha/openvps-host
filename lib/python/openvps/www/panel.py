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

# $Id: panel.py,v 1.5 2005/01/14 23:12:13 grisha Exp $

""" This is a primitive handler that should
    display usage statistics. This requires mod_python
    3.1 or later.
    """

import os
import time
import sys

from mod_python import apache, psp, util

from openvps.common import rrdutil
from openvps.host import cfg
from openvps.host import vsutil

ALLOWED_COMMANDS = ['index',
                    'day_graph',
                    'month_graph',
                    'quarter_graph',
                    'status',
                    'traffic',
                    'start',
                    'stop']

def error(req, msg):
    req.content_type = 'text/html'
    req.write('\n<h1>Error: %s</h1>\n' % msg)
    return apache.OK
              
def handler(req):

    # the URL format is as follows:
    # /vserver_name/command/params...
    
    # figure out the vserver name and command
    path = os.path.normpath(req.uri) # no trailing slash
    parts = path.split('/', 3)

    # defaults
    command, params = 'index', ''

    if len(parts) < 2:
        return error(req, 'request not understood')

    if len(parts) >= 2:
        vserver_name = parts[1]
        vservers = vsutil.list_vservers()
        if not vservers.has_key(vserver_name):
            return error(req, 'request not understood')

    if req.user != vserver_name:
        return error(req, 'request not understood')
        
    if len(parts) > 2:
        command = parts[2]

    if len(parts) > 3:
        params = parts[3]

    if command not in ALLOWED_COMMANDS:
        return error(req, 'request not understood')

    # now call the appropriate action
    self = sys.modules[__name__]
    func = getattr(self, command)

    # call the command with params
    return func(req, vserver_name, params)

#
# Supporting functions
#

def _load_rrd_data(name):

    # build a list of
    # [[year, month, in, out]
    #  [year, month, in, out]...]

    MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
              'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

    data = []

    # location of the bandwidth rrd
    rrd = os.path.join(cfg.VAR_DB_OH, '%s.rrd' % name)

    yyyy, mm = time.localtime()[0:2]
    i, o  = rrdutil.month_total(rrd, yyyy, mm)
    data.append([yyyy, MONTHS[mm-1], i, o])

    yyyy, mm = rrdutil.prev_month(yyyy, mm)
    i, o = rrdutil.month_total(rrd, yyyy, mm)
    data.append([yyyy, MONTHS[mm-1], i, o])

    yyyy, mm = rrdutil.prev_month(yyyy, mm)
    i, o = rrdutil.month_total(rrd, yyyy, mm)
    data.append([yyyy, MONTHS[mm-1], i, o])

    return data

def _tmpl_path(tmpl):

    return os.path.join(cfg.TMPL_DIR, tmpl)

def _base_url(req, ssl=0):
    # lame attempt at guessing base url

    host = req.headers_in.get('host', req.server.server_hostname)

    if ssl:
        base = 'https://' + host + req.uri
    else:
        base = 'http://' + host + req.uri

    return os.path.split(base)[0]

def _navigation_map(req):

    # tag, Text, link, icon_url, submenu

    global_menu = [("status", "Status", "status", None, []),
                   ("traffic", "Bandwidth", "traffic", None, []),
                   ]

    return global_menu

def _global_menu(req, location):

    menu_items = _navigation_map(req)

    m = psp.PSP(req, _tmpl_path('global_menu.html'),
                vars={'menu_items':menu_items,
                      'hlight':location})
    return m

#
# Callable from outside
#

def index(req, name, params):

    return status(req, name, params)


def traffic(req, name, params):

    location = 'traffic'.split(':')

    body_tmpl = _tmpl_path('traffic_body.html')

    data = _load_rrd_data(name)
    body_vars = {'data':data}

    vars = {'global_menu': _global_menu(req, location[0]),
            'body':psp.PSP(req, body_tmpl, vars=body_vars),
            'name':name}
            
    p = psp.PSP(req, _tmpl_path('main_frame.html'),
                vars=vars)

    p.run()

    return apache.OK

def status(req, name, params):
    
    location = 'status'.split(':')

    status = 'stopped'
    if vsutil.is_running(name):
        status = 'running'

    body_tmpl = _tmpl_path('status_body.html')
    body_vars = {'status':status}

    vars = {'global_menu': _global_menu(req, location[0]),
            'body':psp.PSP(req, body_tmpl, vars=body_vars),
            'name':name}
            
    p = psp.PSP(req, _tmpl_path('main_frame.html'),
                vars=vars)

    p.run()

    return apache.OK

def day_graph(req, name, params):

    # location of the bandwidth rrd
    rrd = os.path.join(cfg.VAR_DB_OH, '%s.rrd' % name)

    image = rrdutil.graph(rrd, back=86400, title='Last 24 hours',
                          width=484, height=50)

    req.content_type = 'image/gif'
    req.sendfile(image)
    os.unlink(image)

    return apache.OK

def month_graph(req, name, params):

    # location of the bandwidth rrd
    rrd = os.path.join(cfg.VAR_DB_OH, '%s.rrd' % name)

    image = rrdutil.graph(rrd, back=2592000, title='Last 30 days',
                          width=484, height=50)

    req.content_type = 'image/gif'
    req.sendfile(image)
    os.unlink(image)

    return apache.OK

def quarter_graph(req, name, params):

    # location of the bandwidth rrd
    rrd = os.path.join(cfg.VAR_DB_OH, '%s.rrd' % name)

    image = rrdutil.graph(rrd, back=7614000, title='Last 90 days',
                          width=484, height=50)

    req.content_type = 'image/gif'
    req.sendfile(image)
    os.unlink(image)

    return apache.OK

def stop(req, name, params):

    req.log_error('Stopping vserver %s at request of %s.' % (name, req.user))

    if vsutil.is_running(name):

        vsutil.stop(name)
        time.sleep(3)

    # note - this redirect is relative because absolute won't work with
    # our proxypass proxy
    util.redirect(req, 'status')

def start(req, name, params):

    req.log_error('Starting vserver %s at request of %s.' % (name, req.user))

    if not vsutil.is_running(name):

        vsutil.start(name)
        time.sleep(3)

    # note - this redirect is relative because absolute won't work with
    # our proxypass proxy
    util.redirect(req, 'status')
