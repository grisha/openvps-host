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

# $Id: panel.py,v 1.40 2005/06/17 19:22:51 grisha Exp $

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
from openvps.host import cfg, vsutil, vsmon, vds

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
                    'bwidth',
                    'disk',
                    'cpu',
                    'mem',
                    'rebuild',
                    'dorebuild',
                    'start',
                    'stop',
                    'logout']

TIMEOUT = 60*30 # 30 minutes

SUPER = 'root'

def error(req, msg):
    req.content_type = 'text/html'
    req.write('\n<h1>Error: %s</h1>\n' % msg)
    return apache.OK

def check_authen(req, vserver_name):
    """ If authenticated, return userid """

    try:
        cookies = Cookie.get_cookies(req, Class=RSASignedCookie.RSASignedCookie,
                                     secret=_get_pub_key())
    except RSASignedCookie.RSASignError:
        cookies = None
        
    if not cookies or not cookies.has_key('openvps-user'):
        login(req, vserver_name, message='please log in')
    else:
        try:
            login_time, userid = cookies['openvps-user'].value.split(':', 1)
            if (time.time() - int(login_time)) > TIMEOUT:
                login(req, vserver_name, message='session time-out, please log in again')
                return None
        except:
            login(req, vserver_name, message='please log in')
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
                return login(req, vserver_name)

        # anything else requires authentication
        userid = check_authen(req, vserver_name)
        if not userid:
            return apache.OK

        if (userid != SUPER) and (userid != cfg.PANEL_SUPERUSER) and (userid != vserver_name):
            return error(req, 'request not understood')

        # save it in request to be used later in some places
        req.user = userid

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

    # build a list of (step is in seconds)
    # [[year, month, step, x1, x2]
    #  [year, month, step, x1, x2]...]

    MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
              'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

    data = []

    yyyy, mm = time.localtime()[0:2]
    step, totals  = rrdutil.month_total(rrd, yyyy, mm, dslist)
    data.append([yyyy, MONTHS[mm-1], step] + totals)

    yyyy, mm = rrdutil.prev_month(yyyy, mm)
    step, totals = rrdutil.month_total(rrd, yyyy, mm, dslist)
    data.append([yyyy, MONTHS[mm-1], step] + totals)

    yyyy, mm = rrdutil.prev_month(yyyy, mm)
    step, totals = rrdutil.month_total(rrd, yyyy, mm, dslist)
    data.append([yyyy, MONTHS[mm-1], step] + totals)

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

def _navigation_map(req, vps):

    # tag, Text, link, icon_url, submenu

    admin = [("status", "Status", "status", None, []),
             ("rebuild", "Rebuild", "rebuild", None, []),
             ]

    stats = [("bwidth", "Bandwidth", "bwidth", None, []),
             ("disk", "Disk", "disk", None, []),
             ("cpu", "CPU", "cpu", None, []),
             ("mem", "Memory", "mem", None, []),
             ]

    global_menu = [("admin", "Admin", "status", None, admin),
                   ("stats", "Stats", "stats", None, stats),
                   # note that /billing is expected to be on a different
                   # server, so no submenu here
                   ("account", "Account", "/billing?vps=%s" % vps, None, []),
                   ]

    return global_menu

def _global_menu(req, vps, location):

    if ':' in location:
        hlight, s_hlight = location.split(':')
    else:
        hlight, s_hlight = location, ''

    menu_items = _navigation_map(req, vps)

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

def login(req, vserver_name, message=''):

    if req.method == 'POST':
        # someone is trying to login
                
        fs = util.FieldStorage(req)
        userid = fs.getfirst('userid')
        passwd = fs.getfirst('passwd')
        uri = fs.getfirst('uri')

        vservers = vsutil.list_vservers()
        if ((vserver_name == userid and
             vservers.has_key(vserver_name) and
             vsutil.check_passwd(vserver_name, userid, passwd)) or
            # root
            (userid == SUPER and
             vsutil.check_passwd('/', userid, passwd)) or
            # superuser
            (userid == cfg.PANEL_SUPERUSER and
             crypto.check_passwd_md5(passwd, cfg.PANEL_SUPERUSER_PW))):

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

    # if we got here, either it's not a POST or login failed

    # it's possible that some qargs were passed in

    qargs = {}

    if req.args:
        qargs = util.parse_qs(req.args)
        if qargs.has_key('m'):
            if not message:
                if qargs['m'][0] == '1':
                    message = 'please log in'
                elif qargs['m'][0] == '2':
                    message = 'session time-out, please log in again'
                    
    if qargs.has_key('url'):
        url = qargs['url'][0]
    else:
        url = req.uri

    body_tmpl = _tmpl_path('login_body.html')
    body_vars = {'message':message, 'url':url}

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

    location = 'admin:status'

    status = 'stopped'
    if vsutil.is_running(name):
        status = 'running'
    elif os.path.exists(os.path.join(cfg.ETC_VSERVERS, name, '.rebuild')):
        status = 'rebuilding'

    # avoid caching at all costs
    req.err_headers_out['Pragma'] = 'no-cache'
    req.err_headers_out['Cache-Control'] = 'no-cache'
    req.err_headers_out['Expires'] = 'Tue, 25 Jan 2000 10:30:00 GMT'

    body_tmpl = _tmpl_path('status_body.html')
    body_vars = {'status':status}

    vars = {'global_menu': _global_menu(req, name, location),
            'body':psp.PSP(req, body_tmpl, vars=body_vars),
            'name':name}
            
    p = psp.PSP(req, _tmpl_path('main_frame.html'),
                vars=vars)

    p.run()

    return apache.OK


def stop(req, name, params):

    req.log_error('Stopping vserver %s at request of %s' % (name, req.user))

    if vsutil.is_running(name):

        vsutil.stop(name)
        time.sleep(3)

    # note - this redirect is relative because absolute won't work with
    # our proxypass proxy
    util.redirect(req, 'status')


def start(req, name, params):

    req.log_error('Starting vserver %s at request of %s' % (name, req.user))

    if not vsutil.is_running(name):

        vsutil.start(name)
        time.sleep(3)

    # note - this redirect is relative because absolute won't work with
    # our proxypass proxy
    util.redirect(req, 'status')


def stats(req, name, params):

    return bwidth(req, name, params)


def rebuild(req, name, params):

    location = 'admin:rebuild'

    body_tmpl = _tmpl_path('rebuild_body.html')

    body_vars = {}

    vars = {'global_menu': _global_menu(req, name, location),
            'body':psp.PSP(req, body_tmpl, vars=body_vars),
            'name':name}
            
    p = psp.PSP(req, _tmpl_path('main_frame.html'),
                vars=vars)

    p.run()

    return apache.OK

def dorebuild(req, name, params):

    # make sure it is stopped
    if vsutil.is_running(name):
        return error(req, "%s is running, you must first stop it" % name)

    req.log_error('Rebuilding vds %s at request of %s' % (name, req.user))

    # we could check for "cannot rebuild" error, but since the only
    # cause for that would be a broken shadow file, the user won't be
    # able access the control panel in the first place.

    pid = os.fork()
    if pid == 0:

        # in child

        cmd = '%s openvps-rebuild %s %s' % (cfg.OVWRAPPER, cfg.REFROOTS[0], name)

        pipe = os.popen(cmd, 'r', 0)
        s = pipe.readline()
        while s:
            req.log_error('%s: %s' % (name, s))
            s = pipe.readline()
        pipe.close()

        req.log_error('Rebuild of vds %s at request of %s DONE' % (name, req.user))

        # exit child
        os._exit(0)

    else:

        # in parent

        try:
            time.sleep(3)
            util.redirect(req, 'status')
        finally:
            # wait on the child to avoid a defunct (zombie) process
            os.wait()

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
                '-l', '0',
                'DEF:u=%s:vs_uticks:AVERAGE' % rrd,
                'DEF:s=%s:vs_sticks:AVERAGE' % rrd,
                'AREA:s#FF4500:system ticks/sec',
                'STACK:u#FFA500:user ticks/sec']

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
        data = _load_rrd_data(rrd, ['vs_sticks', 'vs_uticks'])

        body_vars = {'data':data}

        vars = {'global_menu': _global_menu(req, name, location),
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
        height = 60
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
                '-l', '0',
                'DEF:in=%s:vs_in:AVERAGE' % rrd,
                'DEF:out=%s:vs_out:AVERAGE' % rrd,
                'CDEF:inbits=in,8,*',
                'CDEF:outbits=out,8,*',
                'AREA:outbits#7b68ee:bps out',
                'LINE1:inbits#7fff00:bps in']

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

        vars = {'global_menu': _global_menu(req, name, location),
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
                '-l', '0',
                'DEF:d=%s:vs_disk_b_used:AVERAGE' % rrd,
                'CDEF:db=d,1024,*',
                'AREA:db#4eee94:bytes used']

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

        vars = {'global_menu': _global_menu(req, name, location),
                'body':psp.PSP(req, body_tmpl, vars=body_vars),
                'name':name}

        p = psp.PSP(req, _tmpl_path('main_frame.html'),
                    vars=vars)

        p.run()

        return apache.OK


def mem(req, name, params):

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
                '-b', '1024',
                '-c', 'SHADEB#FFFFFF',
                '-c', 'SHADEA#FFFFFF',
                '-l', '0',
                'DEF:v=%s:vs_vm:AVERAGE' % rrd,
                'DEF:r=%s:vs_rss:AVERAGE' % rrd,
                'CDEF:vb=v,1024,*',
                'CDEF:rb=r,1024,*',
                'AREA:rb#36648b:RSS (Resident Segment Size) in bytes',
                'STACK:vb#63b8ff:VM (Virtual Memory Size) in bytes']

        if qargs.has_key('l'):
            args.append('-g')  # no legend
        
        RRD.graph(*args)
        
        req.content_type = 'image/gif'
        req.sendfile(tpath)
        os.unlink(tpath)
        
        return apache.OK

    else:

        location = 'stats:mem'

        body_tmpl = _tmpl_path('mem_body.html')

        rrd = os.path.join(cfg.VAR_DB_OPENVPS, 'vsmon/%s.rrd' % name)
        data = _load_rrd_data(rrd, ['vs_rss', 'vs_vm'])

        body_vars = {'data':data}

        vars = {'global_menu': _global_menu(req, name, location),
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
    # and two [optional] args - start and end

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
    for s in [('start', time.strftime('(%Y-%m-%d %H:%M:%S %Z)',
                                      time.localtime(result['start']))),
              ('end', time.strftime('(%Y-%m-%d %H:%M:%S %Z)',
                                    time.localtime(result['end']))),
              ('step', '(secs)'),
              ('steps', ''),
              ('ticks', '(cpu ticks)'),
              ('vm', '(mem tokens)'),
              ('rss', '(mem tokens)'),
              ('in', '(bytes)'),
              ('out', '(bytes)'),
              ('disk', '(disk tokens)')]:
        
        req.write('%s%s  %s\n' % ((s[0]+':').ljust(lj), result[s[0]], s[1]))

    req.write('\n\n')
    req.write('1 mem token = 1 average KB over 1 minute interval\n')
    req.write('1 disk token = 1 average KB over 1 minute interval\n')


    return apache.OK
