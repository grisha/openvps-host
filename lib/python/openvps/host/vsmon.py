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

# $Id: vsmon.py,v 1.1 2005/01/19 18:08:04 grisha Exp $

# This file contains functions to retrieve various vserver statistics
# (mostly) from the /proc filesystem. Unlike the mon.py module, this
# module needs to be prepared for non-existent context error, always.

import commands
import os
from syslog import syslog, openlog, closelog

# openvps modules
import vsutil
import cfg
import RRD

KEYS = [x[0] for x in cfg.VSMON_DATA_DEF]

def log(s):
    openlog('OpenVPS-vsmon')
    syslog(s)
    closelog()

def limits(xid):

    try:
        s = open('/proc/virtual/%s/limit' % xid).read()
    except IOError:
        return None

    result = {}

    lines = s.splitlines()
    for line in lines:

        # hits is how many times the limit's been hit
        what, max, cur, lim, hits = line.split()

        if what == 'PROC:':
            result['vs_procs'] = int(cur)
            result['vs_procs_lim'] = int(lim)
            result['vs_procs_lhits'] = int(hits)
        elif what == 'VM:':
            result['vs_vm'] = long(cur)
            result['vs_vm_lim'] = long(lim)
            result['vs_vm_lhits'] = long(hits)
        elif what == 'VML:':
            result['vs_vml'] = long(cur)
            result['vs_vml_lim'] = long(lim)
            result['vs_vml_lhits'] = long(hits)
        elif what == 'RSS:':
            result['vs_rss'] = long(cur)
            result['vs_rss_lim'] = long(lim)
            result['vs_rss_lhits'] = long(hits)
        elif what == 'FILES:':
            result['vs_files'] = int(cur)
            result['vs_files_lim'] = int(lim)
            result['vs_files_lhits'] = int(hits)
        elif what == 'SOCK:':
            result['vs_socks'] = int(cur)
            result['vs_socks_lim'] = int(lim)
            result['vs_socks_lhits'] = int(hits)

    return result

def sched(xid):

    try:
        s = open('/proc/virtual/%s/limit' % xid).read()
    except IOError:
        return None

    result = {}

    lines = s.splitlines()
    for line in lines:

        # hticks are ticks spent on hold queue, this only happens with
        # sched_hard

        uticks, sticks, hticks = 0, 0, 0

        if line.startswith('cpu'):
            _u, _s, _h = map(long, line.split()[-3:])
            uticks, sticks, hticks = uticks+_u, sticks+_s, hticks+_h
    
    return {'vs_uticks': uticks, 'vs_sticks': sticks, 'vs_hticks': hticks}

def ipcs(xid):

    # this one actually requires switching contexts

    totshm = 0
    cmd = '%s --xid %s /usr/bin/ipcs -m' % (cfg.CHCONTEXT, xid)
    lines = commands.getoutput(cmd).splitlines()
    for line in lines:
        if not line or line.startswith('----') or line.startswith('key') or line == '\n':
            continue
        key, shmid, owner, perms, bytes, x = line.split(None, 5)
        totshm += int(bytes)

    cmd = '%s --xid %s /usr/bin/ipcs -s' % (cfg.CHCONTEXT, xid)
    lines = commands.getoutput(cmd).splitlines()
    totsem = len(lines) - 3  # a simple trick

    return {'vs_ipc_totshm':totshm, 'vs_ipc_totsem':totsem}

def iptables_info():

    # this one is called from ohbwidth script

    input = {}

    cmd = '/sbin/iptables -xvnL INPUT | grep 0.0.0.0/0'
    s = commands.getoutput(cmd)

    for line in s.splitlines():
        x = line.split()
        bytes, ip = x[1], x[-1]
        input[ip] = bytes

    output = {}

    cmd = '/sbin/iptables -xvnL OUTPUT | grep 0.0.0.0/0'
    s = commands.getoutput(cmd)

    for line in s.splitlines():
        x = line.split()
        bytes, ip = x[1], x[-2]
        output[ip] = bytes

    return input, output

def bandwidth(server, input, output, vservers):

    # this comes from iptables. the data in /proc/virtual/*/cacct isn't
    # all that useful it seems, since it counts internal traffic as well

    i, o = 0L, 0L

    if vservers[server]['interfaces']:

        for ifc in vservers[server]['interfaces']:

            # ignore non eth0 or dummy0 traffic
            if ifc['dev'] not in ['eth0', 'dummy0']:
                continue

            ip = ifc['ip']

            if input.has_key(ip):
                i += long(input[ip])
            else:
                log('WARNING: No iptables INPUT rule exist for ip %s of %s' % (ip, server))

            if output.has_key(ip):
                o += long(output[ip])
            else:
                log('WARNING: No iptables OUTPUT rule exist for ip %s of %s' % (ip, server))

    return {'vs_in':i, 'vs_out':o}


def _rrd_exists(server):
    path = os.path.join(cfg.VAR_DB_OH, '%s-vsmon.rrd' % server)
    return os.path.exists(path)

def _DS(name, dst, hbeat, min='U', max='U'):
    return 'DS:%s:%s:%s:%s:%s' % (name, dst.upper(), hbeat, min, max)

def _RRA(cf, xff, steps, rows):
    return 'RRA:%s:%s:%s:%s' % (cf.upper(), xff, steps, rows)

def _create_rrd(server):

    path = os.path.join(cfg.VAR_DB_OH, '%s-vsmon.rrd' % server)

    args = [path, '-s', '60']

    for n in xrange(len(cfg.VSMON_DATA_DEF)):
        field = cfg.VSMON_DATA_DEF[n]
        if field[1]:
            args.append(_DS(field[0][:19], dst=field[1], hbeat=field[2], min=field[3], max=field[4]))

    # here due to the billing policy we will probably need to keep 40
    # days of 1 minute samples. at the end of 30 days they should be
    # transferred to a real database... although - what can't it be
    # transferred on daily basis? 
        
    args.append(_RRA('AVERAGE', xff=0.5, steps=1, rows=43200))
    #args.append(_RRA('AVERAGE', xff=0.5, steps=1, rows=120))
    #args.append(_RRA('AVERAGE', xff=0.5, steps=5, rows=300))
    #args.append(_RRA('AVERAGE', xff=0.5, steps=30, rows=400))
    #args.append(_RRA('AVERAGE', xff=0.5, steps=450, rows=300))
    args.append(_RRA('AVERAGE', xff=0.5, steps=2160, rows=300))
    args.append(_RRA('AVERAGE', xff=0.5, steps=43200, rows=120))

    #log(`args`)

    RRD.create(args)

def update_rrd(server, data):

    if not _rrd_exists(server):
        _create_rrd(server)
    
    # template
    tmpl = []
    for k in cfg.VSMON_DATA_DEF:
        if k[1]:
           tmpl.append(k[0][:19])

    vals = ['N']
    for k in cfg.VSMON_DATA_DEF:
        if k[1]:
            vals.append('%s' % data[k[0]])

    path = os.path.join(cfg.VAR_DB_OH, '%s-vsmon.rrd' % server)
    args = [path, '-t'] + [':'.join(tmpl)] + [':'.join(vals)]

    log(`args`)
    RRD.update(args)    
    
def collect_stats():

    # this function will walk through xids and collect
    # stats for them and write to rrd all at the same time

    # get iptables counters for all contexts
    input, output = iptables_info()

    # get vserver configs
    vservers = vsutil.list_vservers()

    # walk through /proc/virtual/*, these are active vservers
    virtual = filter(str.isdigit, os.listdir('/proc/virtual'))
    
    for xid in virtual:

        # lookup vserver name (a little complex, but it works)
        server  = filter(lambda x: x[1] == xid, \
                         [(name, vservers[name]['context']) for name in vservers.keys()])[0][0]

        # do all of the above

        data = {}

        try:

            data.update(bandwidth(server, input, output, vservers))
            data.update(limits(xid))
            data.update(sched(xid))
            data.update(ipcs(xid))

            update_rrd(server, data)

        except AttributeError:
            # vserver no longer running
            log('Vserver %s(%s) does not appear to be running' % (server, xid))

    return



