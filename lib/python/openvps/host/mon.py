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

# $Id: mon.py,v 1.6 2006/04/11 23:58:05 grisha Exp $

# This file contains functions to retrieve various server statistics
# (mostly) from the /proc filesystem. It also contains functions to
# encode and sign 'heartbeats' using hmac.

import re
import hmac
import marshal
import commands
import socket

# openvps modules
import cfg

KEYS = [x[0] for x in cfg.MON_DATA_DEF]

def pack_dict(data):

    # since UDP packets should be less than 512 bytes in length, we
    # save space by converting the dictionary to a list where the
    # position in the list dtermines what the value is. the definition
    # for this stored in cfg.MON_DATA_DEF, which means it better match
    # on both ends. It should be OK to send a longer packet than
    # expected, or receive a shorter packet than expected - the
    # trailing stuff is just ignored. So it should be safe to tack
    # elements onto the end of the list.

    r = []

    # since position in the resulting list indicates what it is,
    # absense of value should be denoted by None

    for k in KEYS:
        if data.has_key(k):
            r.append(data[k])
        else:
            r.append(None)

    return r


def marshal_sign(data):

    # marshal sign
    
    m_data = marshal.dumps(data)
    sig = hmac.new(cfg.MON_SECRET, m_data).digest()

    return sig + m_data


def procopen(path):

    # it seems that files in /proc sometimes "do not exist"
    # for brief moments of time XXX why is this?

    try:
        f = open(path)
    except IOError:
        # try again
        f = open(path)

    return f

def hostname():

    # get the hostname

    return {'hostname':socket.getfqdn()}

def loadavg():

    # load average

    s = procopen('/proc/loadavg').read()

    l1, l5, l15, proc, last_pid = s.split()

    nprocs = int(proc.split('/')[1])

    return {'cpu_loadavg1' : float(l1),
            'nprocs' : nprocs}
    
def meminfo():

    # memory information

    result = {}

    lines = procopen('/proc/meminfo').readlines()
    
    for line in lines:
        # only pick the ones we're interested in
        if re.match('^MemTotal|^MemFree|^Cached|'
                    '^Active|^SwapTotal|^SwapFree', line):
            key, val, kb = line.split()
            result['mem_'+key[:-1]] = int(val)

    return result

def stat():

    # info in /proc/stat

    lines = procopen('/proc/stat').readlines()

    for line in lines:
        if re.match('^processes', line):
            return {'forks':long(line.split()[1])}


def net_dev():

    # network device counters

    result = {}

    lines = procopen('/proc/net/dev').readlines()

    for line in lines:
        if ':' in line:
            ifnam, stats = line.strip().split(':')
            rx_b, rx_p,rx_er,rx_dr,x,x,x,x, \
                  tx_b,tx_p,tx_er,tx_dr,x,x,x,x = stats.split()

            if ifnam in ['eth0', 'eth1']:
                result.update({
                    'net_%s_rx_bytes' % ifnam : long(rx_b),
                    'net_%s_tx_bytes' % ifnam : long(tx_b),
                    'net_%s_packets' % ifnam : long(rx_p)+long(tx_p),
                    'net_%s_errors' % ifnam : long(rx_er)+long(tx_er),
                    'net_%s_drop' % ifnam : long(rx_dr)+long(tx_dr)})

    return result

disks = None

def df():

    # disk utilization and other stuff.
    # XXX is there a more efficient way than running df?

    result = {}
    global disks
    devs = []

    # -t ext2 -t ext3 prevents it from hanging when NFS is hosed
    lines = commands.getoutput('/bin/df -k -t ext2 -t ext3').splitlines()

    for line in lines:

        if re.search('/$|/var$|/tmp$|/backup$|/vservers$', line):
            split = line.split()
            used, free, percent, mount = split[-4:]
            if mount == '/':
                mount = '/root'
            result['disk_%s_used' % mount[1:]] = long(used)
            result['disk_%s_free' % mount[1:]] = long(free)

            # make a note of our device names for diskstats()
            if not disks:
                if mount in ['/root', '/backup']:
                    devs.append(split[0].split('/')[-1][:-1])
            
    if not disks:
        # make it a regex
        if len(devs) == 2:
            disks = '%s\\ |%s\\ ' % tuple(devs)
        else:
            # no separate /backup mount
            disks = '%s\\ ' % tuple(devs)

    return result

def dfi():

    # disk utilization  - inodes

    result = {}

    lines = commands.getoutput('/bin/df -i').splitlines()

    for line in lines:

        if re.search('/$|/var$|/tmp$|/backup$|/vservers$', line):
            split = line.split()
            used, free, percent, mount = split[-4:]
            if mount == '/':
                mount = '/root'
            result['disk_%s_i_used' % mount[1:]] = long(used)
            result['disk_%s_i_free' % mount[1:]] = long(free)

    return result

def diskstats():

    # disk device io stats

    result = {}

    lines = procopen('/proc/diskstats').readlines()

    for line in lines:
        if re.search(disks, line):
            x, x, disk, read, x, x, x, write, x, x, x, x, x, x = line.split()
            result['disk_%s_reads' % disk[-1]] = long(read)
            result['disk_%s_writes' % disk[-1]] = long(write)

    return result


shmall, semmns = None, None

def ipcs():

    # kernel.shmall
    global shmall
    if not shmall:
        # note that shmall is in pages (4096 bytes usually), and that it will
        # be rounded off by the kernel to the nearest boundary. it may help
        # to look at ipcs -lm and compare.
        shmall = int(commands.getoutput('/sbin/sysctl -n kernel.shmall').strip())

    # semmns in kernel.sem
    global semmns
    if not semmns:
        sem = commands.getoutput('/sbin/sysctl -n kernel.sem').split()
        semmns = int(sem[1])

    totshm = 0
    lines = commands.getoutput('/usr/bin/ipcs -m').splitlines()
    for line in lines:
        if not line or line.startswith('----') or line.startswith('key') or line == '\n':
            continue
        key, shmid, owner, perms, bytes, x = line.split(None, 5)
        totshm += int(bytes)

    lines = commands.getoutput('/usr/bin/ipcs -s').splitlines()
    totsem = len(lines) - 3  # a simple trick

    return {'ipc_shmall':shmall, 'ipc_totshm':totshm,
            'ipc_semmns':semmns, 'ipc_totsem':totsem}
            

def file_handlers():

    s = procopen('/proc/sys/fs/file-nr').read()
    used, x, avail = s.split()

    return {'fs_handlers_used':long(used),
            'fs_handlers_avail':long(avail)}

def collect_stats():

    # do all of the above

    data = {}

    data.update(hostname())
    data.update(loadavg())
    data.update(meminfo())
    data.update(stat())
    data.update(net_dev())
    data.update(df())
    data.update(dfi())
    data.update(diskstats())
    data.update(ipcs())
    data.update(file_handlers())

    packed = pack_dict(data)

    return marshal_sign(packed)



def cmd_admin_down():

    # create a packet that says "we're going administratively
    # down". This would effectively make every reboot "administrative"
    # downtime since all processes receive a TERM signal, but that's
    # about right - servers do not normally get nicely reboot for no
    # reason.

    # the receiver will look at the packet length, anything of length
    # 3 will be expected to be ['hostname', command_id, data], where
    # data is command-specific stuff.

    data = [hostname()['hostname'], cfg.MON_CMD_ADMIN_DOWN, None]

    return marshal_sign(data)
    

