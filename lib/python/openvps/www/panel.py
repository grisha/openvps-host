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

# $Id: panel.py,v 1.17 2005/02/15 21:49:00 grisha Exp $

""" This is a primitive handler that should
    display usage statistics. This requires mod_python
    3.1 or later.
    """

import os
import time
import sys
import binascii
import tempfile

import RRD

from mod_python import apache, psp, util, Cookie

from openvps.common import rrdutil, crypto, RSASignedCookie
from openvps.host import cfg, vsutil, vsmon

ALLOWED_COMMANDS = ['index',
                    'graph',
                    'graph1',
                    'graph2',
                    'graph3',
                    'day_graph',
                    'month_graph',
                    'quarter_graph',
                    'status',
                    'stats',
                    'traffic',
                    'bwidth',
                    'disk',
                    'cpu',
                    'start',
                    'stop',
                    'logout']

TIMEOUT = 60*30 # 30 minutes

def error(req, msg):
    req.content_type = 'text/html'
    req.write('\n<h1>Error: %s</h1>\n' % msg)
    return apache.OK

def check_authen(req):
    """ If authenticated, return userid """

    try:
        cookies = Cookie.get_cookies(req, Class=RSASignedCookie.RSASignedCookie,
                                     secret=_get_pub_key())
    except RSASignedCookie.RSACookieError:
        cookies = None
        
    if not cookies or not cookies.has_key('openvps-user'):
        login(req, message='please log in')
    else:
        login_time, userid = cookies['openvps-user'].value.split(':', 1)
        if (time.time() - int(login_time)) > TIMEOUT:
            login(req, message='session time-out, please log in again')
            return None

        return userid

              
def handler(req):

    # figure out the vserver name and command
    path = os.path.normpath(req.uri) # no trailing slash
    parts = path.split('/', 4)

    # defaults
    command, params = 'index', ''

    if len(parts) < 2:
        return error(req, 'request not understood')

    if parts[1] == 'admin':
        
        vserver_name = parts[2]
        vservers = vsutil.list_vservers()
        if not vservers.has_key(vserver_name):
            return error(req, 'request not understood')

        if len(parts) > 3:
            command  = parts[3]

            if command == 'login':
                return login(req)

        # anything else requires authentication
        userid = check_authen(req)
        if not userid:
            return apache.OK

        if userid != vserver_name:
            return error(req, 'request not understood')

        if len(parts) > 4:
            params = parts[4]

    elif parts[1] == 'pubkey':

        # hand out our public key
        return pubkey(req)

    elif parts[1] == 'getstats':

        if len(parts) != 4:
            return error(req, 'request not understood')

        name, command = parts[2:]

        return getstats(req, name, command)

    else:
        return error(req, 'request not understood')

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

def _load_rrd_data(rrd, dslist):

    # dslist is a list of DS's in the RRD that we're totalling

    # build a list of
    # [[year, month, x1, x2]
    #  [year, month, x1, x2]...]

    MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
              'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

    data = []

    yyyy, mm = time.localtime()[0:2]
    x  = rrdutil.month_total(rrd, yyyy, mm, dslist)
    data.append([yyyy, MONTHS[mm-1]] + x)

    yyyy, mm = rrdutil.prev_month(yyyy, mm)
    x = rrdutil.month_total(rrd, yyyy, mm, dslist)
    data.append([yyyy, MONTHS[mm-1]] + x)

    yyyy, mm = rrdutil.prev_month(yyyy, mm)
    x = rrdutil.month_total(rrd, yyyy, mm, dslist)
    data.append([yyyy, MONTHS[mm-1]] + x)

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

    stats = [("traffic", "Bandwidth", "traffic", None, []),
             ("disk", "Disk", "disk", None, []),
             ("cpu", "CPU", "cpu", None, []),
             ]

    global_menu = [("status", "Status", "status", None, []),
                   ("stats", "Stats", "stats", None, stats),
                   ]

    return global_menu

def _global_menu(req, location):

    if ':' in location:
        hlight, s_hlight = location.split(':')
    else:
        hlight, s_hlight = location, ''

    menu_items = _navigation_map(req)

    m = psp.PSP(req, _tmpl_path('global_menu.html'),
                vars={'menu_items':menu_items,
                      'hlight':hlight, 's_hlight':s_hlight})
    return m

def _read_priv_key():

    boottime = time.time() - float(open("/proc/uptime").read().split()[0])
    boottime = time.strftime("%Y-%M-%d-%H",(time.localtime(boottime)))

    keypath = os.path.join(cfg.VAR_DB_OPENVPS, cfg.KEYFILE)
    key = crypto.load_key(keypath, boottime)

    return key

def _read_pub_key():

    key = _read_priv_key()

    keypath = os.path.join(cfg.VAR_DB_OPENVPS, cfg.KEYFILE)
    mtime = os.stat(keypath).st_mtime

    return mtime, key.publickey()

_cached_pub_key = None
def _get_pub_key():

    global _cached_pub_key

    keypath = os.path.join(cfg.VAR_DB_OPENVPS, cfg.KEYFILE)

    if _cached_pub_key:
        # it's there, but is it up to date?
        mtime, key = _cached_pub_key
        if os.stat(keypath).st_mtime != mtime:
            _cached_pub_key = _read_pub_key()
    else:
            _cached_pub_key = _read_pub_key()

    return _cached_pub_key[1]

#
# Callable from outside
#

def login(req, message=''):

    if req.method == 'POST':
        # someone is trying to login
                
        fs = util.FieldStorage(req)
        userid = fs.getfirst('userid')
        passwd = fs.getfirst('passwd')
        uri = fs.getfirst('uri')

        vserver_name = userid

        vservers = vsutil.list_vservers()
        if vservers.has_key(vserver_name) and vsutil.check_passwd(vserver_name, userid, passwd):

            # plant the cookie
            key = _read_priv_key()
            cookie = RSASignedCookie.RSASignedCookie('openvps-user', "%d:%s" % (time.time(), userid), key)
            cookie.path = '/'
            Cookie.add_cookie(req, cookie)

            if uri and not uri.endswith('login'):
                util.redirect(req, str(uri))
            else:
                util.redirect(req, '/admin/%s/status' % vserver_name)

        else:
             message = 'invalid login or password'   

    body_tmpl = _tmpl_path('login_body.html')
    body_vars = {'message':message, 'url':req.uri}

    vars = {'global_menu': '', 
            'body':psp.PSP(req, body_tmpl, vars=body_vars),
            'name':''}
            
    p = psp.PSP(req, _tmpl_path('main_frame.html'),
                vars=vars)

    p.run()

    return apache.OK

def logout(req, name, params):

    Cookie.add_cookie(req, Cookie.Cookie('openvps-user', '', path='/'))
    util.redirect(req, '/admin/%s/login' % name)

    return apache.OK

def pubkey(req):

    req.context_type = 'text/plain'
    req.write(crypto.rsa2str((_get_pub_key())))

    return apache.OK

def index(req, name, params):

    return status(req, name, params)


def status(req, name, params):

    location = 'status'

    status = 'stopped'
    if vsutil.is_running(name):
        status = 'running'

    body_tmpl = _tmpl_path('status_body.html')
    body_vars = {'status':status}

    vars = {'global_menu': _global_menu(req, location),
            'body':psp.PSP(req, body_tmpl, vars=body_vars),
            'name':name}
            
    p = psp.PSP(req, _tmpl_path('main_frame.html'),
                vars=vars)

    p.run()

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


def stats(req, name, params):

    return traffic(req, name, params)


def traffic(req, name, params):

    location = 'stats:traffic'

    body_tmpl = _tmpl_path('traffic_body.html')

    rrd = os.path.join(cfg.VAR_DB_OH, '%s.rrd' % name)
    data = _load_rrd_data(rrd, ['in', 'out'])
    body_vars = {'data':data}

    vars = {'global_menu': _global_menu(req, location),
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

    # location of the vsmon rrd
    rrd = os.path.join(cfg.VAR_DB_OH, '%s.rrd' % name)

    image = rrdutil.graph(rrd, back=7614000, title='Last 90 days',
                          width=484, height=50)

    req.content_type = 'image/gif'
    req.sendfile(image)
    os.unlink(image)

    return apache.OK


def cpu(req, name, params):

    if params.startswith('graph'):

        if not req.args:
            return error(req, 'Not sure what you mean')

        qargs = util.parse_qs(req.args)
        
        if not qargs.has_key('s'):
            return error(req, 'Where do I start?')

        start = '-'+qargs['s'][0]
        width = 484
        height = 70
        nolegend = ''
        if qargs.has_key('l'):
            nolegend = '-g'  # no legend

        # how many days back?
        secs = abs(int(start))
        if secs < 60*60*24:
            # we're talking hours
            title = 'last %d hours' % (secs/(60*60))
        else:
            title = 'last %d days' % (secs/(60*60*24))

        rrd = os.path.join(cfg.VAR_DB_OPENVPS, 'vsmon/%s.rrd' % name)
        tfile, tpath = tempfile.mkstemp('.gif', 'oh')
        os.close(tfile)

        args = [tpath, '--start', start,
                  '--title', title,
                  '-w', str(width),
                  '-h', str(height),
                  '-c', 'SHADEB#FFFFFF',
                  '-c', 'SHADEA#FFFFFF',
                  'DEF:u=%s:vs_uticks:AVERAGE' % rrd,
                  'DEF:s=%s:vs_sticks:AVERAGE' % rrd,
                  'AREA:s#FF4500:user ticks',
                  'STACK:u#FF8000:system ticks']

        if qargs.has_key('l'):
            args.append('-g')  # no legend
        
        RRD.graph(*args)
        
        req.content_type = 'image/gif'
        req.sendfile(tpath)
        os.unlink(tpath)
        
        return apache.OK

    else:

        location = 'stats:cpu'

        body_tmpl = _tmpl_path('cpu_body.html')

        rrd = os.path.join(cfg.VAR_DB_OPENVPS, 'vsmon/%s.rrd' % name)
        data = _load_rrd_data(rrd, ['vs_uticks', 'vs_sticks'])

        body_vars = {'data':data}

        vars = {'global_menu': _global_menu(req, location),
                'body':psp.PSP(req, body_tmpl, vars=body_vars),
                'name':name}

        p = psp.PSP(req, _tmpl_path('main_frame.html'),
                    vars=vars)

        p.run()

        return apache.OK


def bwidth(req, name, params):

    if params.startswith('graph'):

        if not req.args:
            return error(req, 'Not sure what you mean')

        qargs = util.parse_qs(req.args)
        
        if not qargs.has_key('s'):
            return error(req, 'Where do I start?')

        start = '-'+qargs['s'][0]
        width = 484
        height = 56
        nolegend = ''
        if qargs.has_key('l'):
            nolegend = '-g'  # no legend

        # how many days back?
        secs = abs(int(start))
        if secs < 60*60*24:
            # we're talking hours
            title = 'last %d hours' % (secs/(60*60))
        else:
            title = 'last %d days' % (secs/(60*60*24))

        rrd = os.path.join(cfg.VAR_DB_OPENVPS, 'vsmon/%s.rrd' % name)
        tfile, tpath = tempfile.mkstemp('.gif', 'oh')
        os.close(tfile)

        args = [tpath, '--start', start,
                  '--title', title,
                  '-w', str(width),
                  '-h', str(height),
                  '-c', 'SHADEB#FFFFFF',
                  '-c', 'SHADEA#FFFFFF',
                'DEF:in=%s:vs_in:AVERAGE' % rrd,
                'DEF:out=%s:vs_out:AVERAGE' % rrd,
                'CDEF:inbits=in,8,*',
                'CDEF:outbits=out,8,*',
                'AREA:inbits#00FF00:bps in',
                'LINE1:outbits#0000FF:bps out']

        if qargs.has_key('l'):
            args.append('-g')  # no legend
        
        RRD.graph(*args)
        
        req.content_type = 'image/gif'
        req.sendfile(tpath)
        os.unlink(tpath)
        
        return apache.OK

    else:

        location = 'stats:bwidth'

        body_tmpl = _tmpl_path('bwidth_body.html')

        rrd = os.path.join(cfg.VAR_DB_OPENVPS, 'vsmon/%s.rrd' % name)
        data = _load_rrd_data(rrd, ['vs_in', 'vs_out'])

        body_vars = {'data':data}

        vars = {'global_menu': _global_menu(req, location),
                'body':psp.PSP(req, body_tmpl, vars=body_vars),
                'name':name}

        p = psp.PSP(req, _tmpl_path('main_frame.html'),
                    vars=vars)

        p.run()

        return apache.OK


def disk(req, name, params):

    if params.startswith('graph'):

        if not req.args:
            return error(req, 'Not sure what you mean')

        qargs = util.parse_qs(req.args)
        
        if not qargs.has_key('s'):
            return error(req, 'Where do I start?')

        start = '-'+qargs['s'][0]
        width = 484
        height = 56
        nolegend = ''
        if qargs.has_key('l'):
            nolegend = '-g'  # no legend

        # how many days back?
        secs = abs(int(start))
        if secs < 60*60*24:
            # we're talking hours
            title = 'last %d hours' % (secs/(60*60))
        else:
            title = 'last %d days' % (secs/(60*60*24))

        rrd = os.path.join(cfg.VAR_DB_OPENVPS, 'vsmon/%s.rrd' % name)
        tfile, tpath = tempfile.mkstemp('.gif', 'oh')
        os.close(tfile)

        args = [tpath, '--start', start,
                  '--title', title,
                  '-w', str(width),
                  '-h', str(height),
                  '-c', 'SHADEB#FFFFFF',
                  '-c', 'SHADEA#FFFFFF',
                'DEF:d=%s:vs_disk_b_used:AVERAGE' % rrd,
                'AREA:d#00FF00:bytes used']

        if qargs.has_key('l'):
            args.append('-g')  # no legend
        
        RRD.graph(*args)
        
        req.content_type = 'image/gif'
        req.sendfile(tpath)
        os.unlink(tpath)
        
        return apache.OK

    else:

        location = 'stats:disk'

        body_tmpl = _tmpl_path('disk_body.html')

        rrd = os.path.join(cfg.VAR_DB_OPENVPS, 'vsmon/%s.rrd' % name)
        data = _load_rrd_data(rrd, ['vs_disk_b_used'])

        body_vars = {'data':data}

        vars = {'global_menu': _global_menu(req, location),
                'body':psp.PSP(req, body_tmpl, vars=body_vars),
                'name':name}

        p = psp.PSP(req, _tmpl_path('main_frame.html'),
                    vars=vars)

        p.run()

        return apache.OK


def getstats(req, name, command):

    # we expect two commands:
    #   sum
    #   list
    # and two [optional] - start and end

    start, end = None, None

    if req.args:
        qs = util.parse_qs(req.args)
        if qs.has_key('start'):
            start = qs['start'][0]
        if qs.has_key('end'):
            end = qs['end'][0]

    result = vsmon.report_sum(name, start, end)

    lj = 15
    req.write('%s%s\n' % ('name:'.ljust(15), name))
    for s in ['start', 'end', 'step', 'steps', 'ticks',
              'vm', 'rss', 'in', 'out', 'disk']:
        req.write('%s%s\n' % ((s+':').ljust(lj), result[s]))

    return apache.OK
