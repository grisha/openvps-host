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

# $Id: panel.py,v 1.10 2005/02/08 17:17:30 grisha Exp $

""" This is a primitive handler that should
    display usage statistics. This requires mod_python
    3.1 or later.
    """

import os
import time
import sys
import binascii

from mod_python import apache, psp, util, Cookie

from openvps.common import rrdutil, crypto, RSASignedCookie
from openvps.host import cfg, vsutil

ALLOWED_COMMANDS = ['index',
                    'day_graph',
                    'month_graph',
                    'quarter_graph',
                    'status',
                    'traffic',
                    'start',
                    'stop']

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

        return userid

              
def handler(req):

    # the URL format is as follows:
    # /vserver_name/command/params...
    
    # figure out the vserver name and command
    path = os.path.normpath(req.uri) # no trailing slash
    parts = path.split('/', 4)

    # defaults
    command, params = 'index', ''

    if len(parts) < 2:
        return error(req, 'request not understood')

    if parts[1] == 'admin':
        
        # requires authentication
        userid = check_authen(req)
        if not userid:
            return apache.OK

        vserver_name = parts[2]
        vservers = vsutil.list_vservers()
        if not vservers.has_key(vserver_name):
            return error(req, 'request not understood')

        if userid != vserver_name:
            return error(req, 'request not understood')

        if len(parts) > 3:
            command  = parts[3]

        if len(parts) > 4:
            params = parts[4]

    elif parts[1] == 'pubkey':

        # hand out our public key
        return pubkey(req)

    elif parts[1] == 'login':
        return login(req)

    elif parts[1] == 'logout':
        return logout(req)

    elif parts[1] == 'stats':
        return stats(req)

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

            if uri and uri != '/login':
                req.log_error('redirecting to '+uri)
                util.redirect(req, str(uri))
            else:
                util.redirect(req, '/admin/%s/' % vserver_name)

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

def logout(req):

    Cookie.add_cookie(req, Cookie.Cookie('openvps-user', ''))
    util.redirect(req, '/login')

    return apache.OK

def pubkey(req):

    req.context_type = 'text/plain'
    req.write(binascii.hexlify(_get_pub_key()))

    return apache.OK

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

def stats(req):

    req.write('stats here')

    return apache.OK
