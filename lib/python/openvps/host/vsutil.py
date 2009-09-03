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

# $Id: vsutil.py,v 1.31 2009/09/03 19:53:11 grisha Exp $

""" Vserver-specific functions """

import os
import commands
import struct
import fcntl
import sys
import tempfile
import pprint
import time

import cfg
from openvps.common import util

import vserver

def is_vserver_kernel():
    """ Are we running on a VServer kernel? """

    kinfo = commands.getoutput('/bin/uname -a').split()[2]
    return '-vs' in kinfo

def _read_val(fname):
    if os.path.exists(fname):
        return open(fname).read().strip()

def _read_link(fname):
    if os.path.islink(fname):
        return os.readlink(fname)

def get_vserver_config(name):

    # We do not take a 'generic' approach and simply read everything
    # in the directory, but look for specific files and ignore others. This
    # is because the sematics of each parameter are too complex to be generic, e.g.
    # in the interfaces directory, the alphabetical order of the directory determins
    # the order in which they are turned up.

    cfgdir = os.path.join(cfg.ETC_VSERVERS, name)

    if not os.path.isdir(cfgdir):
        # not a valid vserver
        return None

    config = {'cfgdir':cfgdir}

    for singleval in ['context', 'nice']:
        config[singleval] = _read_val(os.path.join(cfgdir, singleval))

    for symlink in ['run', 'run.rev', 'vdir']:
        config[symlink] = _read_link(os.path.join(cfgdir, symlink))

    config['flags'] = _read_val(os.path.join(cfgdir, 'flags'))
    if config['flags']: config['flags'] = config['flags'].split()
    
    config['hostname'] = _read_val(os.path.join(cfgdir, 'uts/nodename'))

    interfaces = []
    ints = os.listdir(os.path.join(cfgdir, 'interfaces'))
    ints.sort()

    for int in ints:
        ifconfig = {}
        ifconfig['ip'] = _read_val(os.path.join(cfgdir, 'interfaces', int, 'ip'))
        ifconfig['mask'] = _read_val(os.path.join(cfgdir, 'interfaces', int, 'mask'))
        ifconfig['dev'] = _read_val(os.path.join(cfgdir, 'interfaces', int, 'dev'))
        ifconfig['name'] = _read_val(os.path.join(cfgdir, 'interfaces', int, 'name'))
        ifconfig['dir'] = int
        interfaces.append(ifconfig)

    config['interfaces'] = interfaces

    return config

def save_vserver_config(name, ip, xid, hostname=None, dev=cfg.DFT_DEVICE,
                        vpn_ip=None, vpn_mask='255.255.255.0', vps_arch='i386'):

    if not hostname:
        hostname = name

    dirname = os.path.join(cfg.ETC_VSERVERS, name)
    if os.path.exists(dirname):
        print 'ERROR: %s already exists, please remove it first' % dirname
        sys.exit()
        
    print 'Making config dir %s' % dirname
    os.mkdir(dirname)

    print 'Writing config files...'

    # context
    open(os.path.join(dirname, 'context'), 'w').write(xid+'\n')

    # flags
    open(os.path.join(dirname, 'flags'), 'w').write(cfg.DFT_FLAGS)

    # schedule
    f = open(os.path.join(dirname, 'schedule'), 'w')
    for k in ['fill-rate', 'interval', 'tokens', 'tokens-min', 'tokens-max']:
        f.write('%d\n' % cfg.DFT_SCHED[k])
    f.write('0\n') # obsolete cpu mask
    f.close()

    # uts
    os.mkdir(os.path.join(dirname, 'uts'))

    # nodename
    open(os.path.join(dirname, 'uts', 'nodename'), 'w').write(hostname+'\n')

    # nice
    open(os.path.join(dirname, 'nice'), 'w').write(cfg.DFT_NICE+'\n')

    # bcapabilities
    # XXX
    # This may be FC4-pam-specific, see thread on "audit interface" on
    # VServer list these are CAP_AUDIT_WRITE and CAP_AUDIT_CONTROL
    open(os.path.join(dirname, 'bcapabilities'), 'w').write('^29\n^30\n')

    # ccapabilities
    open(os.path.join(dirname, 'ccapabilities'), 'w').write('mount\n')

    # rlimits
    os.mkdir(os.path.join(dirname, 'rlimits'))
    for limit in cfg.RLIMITS.keys():
        open(os.path.join(dirname, 'rlimits', limit), 'w').write('%s\n' % cfg.RLIMITS[limit])

    # run
    os.symlink('/var/run/vservers/%s' % name, os.path.join(dirname, 'run'))

    # run.rev
    os.symlink(os.path.join(cfg.ETC_VSERVERS, '.defaults/run.rev'), os.path.join(dirname, 'run.rev'))

    # vdir
    root = os.path.join(cfg.VSERVERS_ROOT, name)
    os.symlink(root, os.path.join(dirname, 'vdir'))

    # interfaces
    os.mkdir(os.path.join(dirname, 'interfaces'))

    # add the ip (mask must be /32, or they will end up grouped)
    add_vserver_ip(name, ip, cfg.DFT_DEVICE, '255.255.255.255')

    if vpn_ip:
        # add the VPN ip 
        add_vserver_ip(name, vpn_ip, 'tap_'+name, vpn_mask)

    # fstab
    # here we process an optional substitution - %(vps), this is so that the vps
    # name could (optionally) be inserted into fstab.
    open(os.path.join(dirname, 'fstab'), 'w').write(cfg.VS_FSTAB % {'vps':name})

    # apps/init/mark (this makes the vserver start at startup by vservers-default)
    os.mkdir(os.path.join(dirname, 'apps'))
    os.mkdir(os.path.join(dirname, 'apps', 'init'))
    open(os.path.join(dirname, 'apps', 'init', 'mark'), 'w').write('default\n')

    # apps/init/style (we want real init)
    open(os.path.join(dirname, 'apps', 'init', 'style'), 'w').write('plain\n')

    # fix up guest architecture if it is not x86_64
    host_arch = os.uname()[-1]
    if host_arch == 'x86_64' and vps_arch != 'x86_64':
        print 'Fixing guest personality to i386...'
        open(os.path.join(dirname, 'personality'), 'w').write('linux_32bit\n')
        open(os.path.join(dirname, 'uts', 'machine'), 'w').write('i686\n')

    print 'Done'

def add_vserver_ip(name, ip, dev, mask):

    # what is the next interface number?
    conf = get_vserver_config(name)
    inums = []
    for i in conf['interfaces']:
        inums.append(i['dir'])

    next = None
    for n in map(str, range(64)):
        if n not in inums:
            next = str(n)
            break

    if next is None:
        raise 'Too many interfaces for this vserver?'
    
    # now write it
    dirname = os.path.join(cfg.ETC_VSERVERS, name)
    
    # interface 
    os.mkdir(os.path.join(dirname, 'interfaces', next))

    # interface ip
    open(os.path.join(dirname, 'interfaces', next, 'ip'), 'w').write(ip+'\n')

    # interface  mask 
    open(os.path.join(dirname, 'interfaces', next, 'mask'), 'w').write(mask+'\n')
    
    # interface  name
    # for tap interface we do not want a name (this is a bit of a hack)
    if not dev.startswith('tap'):
        # we append next because some people want multiple IP's and name has to be unique
        # per interface
        open(os.path.join(dirname, 'interfaces', next, 'name'), 'w').write(name+next+'\n')

    # interface  dev
    open(os.path.join(dirname, 'interfaces', next, 'dev'), 'w').write(dev+'\n')

def list_vservers():
    """ Return a dictionary of vservers """

    result = {}

    for file in os.listdir(cfg.ETC_VSERVERS):

        cfgdir = os.path.join(cfg.ETC_VSERVERS, file)

        if not os.path.isdir(cfgdir) or file.startswith('.'):
            # not a config 
            continue

        result[file] = get_vserver_config(file)

    return result

## def print_vserver_ips():

##     # this is used by the /etc/init.d/ohresources shell script

##     vl = list_vservers()
##     for v in vl.keys():
##         for i in vl[v]['interfaces']:
##             print '%s:%s' % (i['dev'], i['ip'])

def guess_vserver_device():
    """ Guess which device is the one mounting our vservers partition """

    s = commands.getoutput('/bin/mount | /bin/grep tagxid | /usr/bin/head -n 1')
    device = s.split()[0]

    return device

def set_file_immutable_unlink(path):
    """ Sets the ext2 immutable-unlink flag. This is the special
        flag that only exists in a vserver kernel."""

    return vserver.set_file_attr(path, {'immutable':True, 'iunlink':True})

def is_file_immutable_unlink(path):
    """ Check wither the iunlink flag is set """

    x = vserver.get_file_attr(path)
    return x.has_key('iunlink') and x.has_key('immutable') and x['iunlink'] and x['immutable']


def set_file_xid(path, xid):
    """ Set xid of a file """
    
    vserver.set_file_xid(path, xid)

def get_disk_limits(xid):

    # this routine supports both old vdlimit written by Herbert and
    # the new vdlimit in alpha tools. Eventually the old support can
    # be removed.

    r = {}

    # assume new style
    cmd = '%s --xid %s %s' % (cfg.VDLIMIT, xid, cfg.VSERVERS_ROOT)
    s =  commands.getoutput(cmd)

    if not 'invalid option' in s:

        if 'No such process' in s:
            # no limits for this vserver
            return None
        
        lines = s.splitlines()
        for line in lines:

            if '=' in line:
                
                key, val = line.split('=')
                
                if line.startswith('space_used='):
                    r['b_used'] = val
                elif line.startswith('space_total='):
                    r['b_total'] = val
                elif line.startswith('inodes_used='):
                    r['i_used'] = val
                elif line.startswith('inodes_total='):
                    r['i_total'] = val
                elif line.startswith('reserved='):
                    r['root'] = val

    else:
        
        # this must be old vdlimit
        # XXX this can be removed later

        cmd = '%s -x %s %s' % (cfg.VDLIMIT, xid, cfg.VSERVERS_ROOT)
        s =  commands.getoutput(cmd)

        lines = s.splitlines()
        for line in lines:

            if line == 'vc_get_dlimit: No such process':
                continue

            key, val = line.split(': ')

            if val == '0,0,0,0,0':
                return None

            r['b_used'], r['b_total'], r['i_used'], r['i_total'], r['root'] = \
                         val.split(',')

    return r

def set_disk_limits(xid, b_used, b_total, i_used, i_total, root, mpoint):

    # assume new style vdlimit, but be prepared to deal with the old one as well

    cmd = '%s --xid %s --set space_used=%s --set space_total=%s ' \
          '--set inodes_used=%s --set inodes_total=%s --set reserved=%s %s' \
          %  (cfg.VDLIMIT, xid, b_used, b_total, i_used, i_total, root, mpoint)

    s = commands.getoutput(cmd)
    if 'invalid option' in s:
        # old vdlimit (XXX this can go away soon)
        print ' WARNING! OLD VDLIMIT! Upgrade your util-vserver to 0.30.207+. Using old vdlimit:'
        cmd = '%s -a -x %s -S %s,%s,%s,%s,%s %s' % \
              (cfg.VDLIMIT, xid, b_used, b_total, i_used, i_total, root, mpoint)
        print ' ', cmd
        print commands.getoutput(cmd)

def unify(src, dst):
    """ Unify destination and source """

    # NOTE: at this point it is assumed files are unifiable

    # get a temp file name
    dir = os.path.split(src)[0]
    tmp_handle, tmp_path = tempfile.mkstemp(dir=dir)
    os.close(tmp_handle)

    # rename the destination, in case we need to back out
    os.rename(dst, tmp_path)

    # link source to destination
    try:
        os.link(src, dst)
    except:
        # back out
        print 'Could not link %s -> %s, backing out' % (src, dst)
        try:
            if os.path.exists(dst):
                os.unlink(dst)
            os.rename(tmp_path, dst)
        except:
            print 'Could not back out!!! the destination file is still there as', tmp_file
            raise exceptions.OSError

    # done, remove the temp file
    os.unlink(tmp_path)

# the following function can be called from apache, in which case
# they'll be run via the suid ovwrapper, which will make sure the
# caller belongs to the apache group

def is_running(vserver):

    if os.getuid() == 0:
        # run directly
        s = commands.getoutput(cfg.VSERVER_STAT)
    else:
        s = commands.getoutput('%s vserver-stat' % cfg.OVWRAPPER)

    lines = s.splitlines()
    for line in lines:
        if line.startswith('CTX'):
            continue
        if vserver == line.split()[7]:
            return True
        
    return False

def start(vserver):

    if os.getuid() == 0:
        # run directly
        return commands.getoutput('%s %s start' % (cfg.VSERVER, vserver))
    else:

        # in this case assume we're called from mod_python. things aren't nearly
        # as simple - if we were to start the vserver directly, its init process would
        # inherit all our file descriptors for as long as the vserver will run,
        # making it impossible to restart httpd on the main server since its ip/port
        # will remain open. so we have to fork then close all file descriptors.

        pid = os.fork()
        if pid == 0:
            
            # in child

            # now close all file descriptors
            for fd in range(os.sysconf("SC_OPEN_MAX")):
                try:
                    os.close(fd)
                except OSError:   # ERROR (ignore)
                    pass

            # only now is it OK to do our thing
            os.system('%s vserver-start %s > /dev/null 2>&1 &' % (cfg.OVWRAPPER, vserver))

            # exit child
            os._exit(0)
            
        else:
            # wait on the child to avoid a defunct (zombie) process
            os.wait()


def stop(vserver):

    if os.getuid() == 0:
        # run directly
        return commands.getoutput('%s %s stop' % (cfg.VSERVER, vserver))
    else:
        return commands.getoutput('%s vserver-stop %s' % (cfg.OVWRAPPER, vserver))


def unsuspend(vserver):

    ## update the vserver config to make sure it does not
    ## start automatically on startup

    mark_path = os.path.join(cfg.ETC_VSERVERS, vserver, 'apps/init/mark')

    s = open(mark_path).read().strip()

    if s == '*default':
        open(mark_path, 'w').write('default\n')

    ## not start it if it's not running
    if not is_running(vserver):
        start(vserver)


def suspend(vserver):

    ## update the vserver config to make sure it does not
    ## start automatically on startup

    mark_path = os.path.join(cfg.ETC_VSERVERS, vserver, 'apps/init/mark')

    s = open(mark_path).read().strip()

    if s == 'default':
        open(mark_path, 'w').write('*default\n')

    ## now stop it if it's running
    if is_running(vserver):
        stop(vserver)


def iptables_rules(vserver):

    print 'Adding iptables rules for bandwidth montoring and firewall'

    # XXX hack - we need some modules
    _ipt_init()

    # get vserver IPs
    ips = [(x['ip'], x['dev']) for x in get_vserver_config(vserver)['interfaces']]

    chain_name = 'ov_' + vserver
    block_chain_name = 'ov_' + vserver + '_block'

    # create fw chain ?
    cmd = '/sbin/iptables -nL %s' % chain_name
    s = commands.getoutput(cmd)
    if 'No chain' in s or 'Table does not exist' in s:
        cmd = '/sbin/iptables -N %s' % chain_name
        print ' ', cmd
        commands.getoutput(cmd)
        
    # create fw chain ?
    cmd = '/sbin/iptables -nL %s' % block_chain_name
    s = commands.getoutput(cmd)
    if 'No chain' in s or 'Table does not exist' in s:
        cmd = '/sbin/iptables -N %s' % block_chain_name
        print ' ', cmd
        commands.getoutput(cmd)
        
    # now for every IP check rules
    
    for ip, dev in ips:

        if not dev.startswith('tap'):

            # does a legacy rule exist?
            cmd = '/sbin/iptables -L INPUT -n | grep %s | grep -v %s' % (ip, chain_name)
            if commands.getoutput(cmd):

                # kill it
                cmd = '/sbin/iptables -D INPUT -i %s -d %s' % (cfg.DFT_DEVICE, ip)
                print ' ', cmd
                commands.getoutput(cmd)

            # do our rules exist?
            cmd = '/sbin/iptables -L INPUT -n | grep %s | grep %s' % (ip, chain_name)
            if not commands.getoutput(cmd):

                # create a rule to jump to block chain
                cmd = '/sbin/iptables -A INPUT -i %s -d %s -j %s' % (cfg.DFT_DEVICE, ip,
                                                               block_chain_name)
                print ' ', cmd
                commands.getoutput(cmd)

                # create a rule to jump to fw chain
                cmd = '/sbin/iptables -A INPUT -i %s -d %s -j %s' % (cfg.DFT_DEVICE, ip,
                                                               chain_name)
                print ' ', cmd
                commands.getoutput(cmd)

            else:
                print 'INPUT rules already exists for %s, skipping' % ip

            # does OUTPUT rule exist?
            cmd = '/sbin/iptables -L OUTPUT -n | grep %s' % ip
            if not commands.getoutput(cmd):

                cmd = '/sbin/iptables -A OUTPUT -o %s -s %s' % (cfg.DFT_DEVICE, ip)
                print ' ', cmd
                commands.getoutput(cmd)    

            else:
                print 'OUTPUT rule already exists for %s, skipping' % ip


def is_tc_base_up():

    # is the basic tc stuff there?

    cmd = '/sbin/tc class ls dev %s | grep "class htb 10:2 root"' % cfg.DFT_DEVICE
    s = commands.getoutput(cmd)

    return 'class htb' in s

def set_tc_class(vserver):

    if not is_tc_base_up():

        print 'tc (traffic shaping) base not set up, skipping it. try "service ovtc start"'

    else:

        print 'Setting tc (traffic shaping) class for', vserver

        # is there a file? the format is ceil[:n], e.g. "5mbit" or "5mbit:12"
        n, ceil = None, cfg.DFT_VS_CEIL
        try:
            parts  = open(os.path.join(cfg.VAR_DB_OPENVPS, 'tc', vserver)).read().strip().split(':')
            if len(parts) == 1:
                 ceil = parts[0]
            else:
                 ceil, n = parts[:2]

            # is there a cap? a cap a "shadow" overriding limit not visible to the VPS user.
            cap_path = os.path.join(cfg.VAR_DB_OPENVPS, 'tc', vserver+'-CAP')
            if os.path.exists(cap_path):
                ceil = open(cap_path).read().strip()
                 
        except IOError: pass

        vs = list_vservers()

        if n is None:
            # default to 1 + last three digits of the xid
            n = '1' + vs[vserver]['context'][-3:]

        # is there a filter by this id?

        cmd = '/sbin/tc filter ls dev %s parent 10: | grep "flowid 10:%s"' % (cfg.DFT_DEVICE, n)
        print '   ', cmd; sys.stdout.flush; time.sleep(.1) #X+
        s = commands.getoutput(cmd)
        print '   [done]', cmd; sys.stdout.flush; time.sleep(.1) #X+
        
        if 'flowid' in s:

            # kill them (see http://mailman.ds9a.nl/pipermail/lartc/2004q4/014500.html)

            for filter in s.splitlines():

                # find the prio, handle, kind
                parts = filter.split()
                handle = parts[parts.index('fh')+1]
                prio = parts[parts.index('pref')+1]
                kind = parts[parts.index('pref')+2]

                cmd = '/sbin/tc filter del dev %s parent 10: prio %s handle %s %s' % \
                      (cfg.DFT_DEVICE, prio, handle, kind)
                print '   ', cmd; sys.stdout.flush; time.sleep(.1) #X+
                #print '   ', cmd
                s = commands.getoutput(cmd)
                if s:
                    print s
                print '   [done]', cmd; sys.stdout.flush; time.sleep(.1) #X+

        # is there a classes ?

        cmd = '/sbin/tc class ls dev %s parent 10:2 | grep "htb 10:%s"' % (cfg.DFT_DEVICE, n)
        print '   ', cmd; sys.stdout.flush; time.sleep(.1) #X+
        s = commands.getoutput(cmd)
        print '   [done]', cmd; sys.stdout.flush; time.sleep(.1) #X+

        if 'class' in s:

            # kill it too
            cmd = '/sbin/tc class del dev %s parent 10:2 classid 10:%s' % (cfg.DFT_DEVICE, n)
            print '   ', cmd; sys.stdout.flush; time.sleep(.1) #X+
            #print '   ', cmd
            s = commands.getoutput(cmd)
            if s:
                print s
            print '   [done]', cmd; sys.stdout.flush; time.sleep(.1) #X+

        # now we can do our thing

        cmd = '/sbin/tc class add dev %s parent 10:2 classid 10:%s htb rate %s ceil %s burst 15k' % \
              (cfg.DFT_DEVICE, n, cfg.DFT_VS_RATE, ceil)
        print '   ', cmd; sys.stdout.flush; time.sleep(.1) #X+
        #print '   ', cmd
        s = commands.getoutput(cmd)
        if s:
            print s
        print '   [done]', cmd; sys.stdout.flush; time.sleep(.1) #X+

        U32 = '/sbin/tc filter add dev %s protocol ip parent 10:0 prio 1 u32' % cfg.DFT_DEVICE
        
        for i in vs[vserver]['interfaces']:
            if i['dev'] == cfg.DFT_DEVICE or i['dev'].startswith('dummy'):

                # dummy is here because its packets actually enter via DFT_DEVICE in
                # a DSR load-balancing scenario
                
                cmd = '%s match ip src %s/32 flowid 10:%s' % (U32, i['ip'], n)
                print '   ', cmd; sys.stdout.flush; time.sleep(.1) #X+
                #print '   ', cmd
                s = commands.getoutput(cmd)
                if s:
                    print s
                print '   [done]', cmd; sys.stdout.flush; time.sleep(.1) #X+


def set_bwlimit(vserver, limit, cap=None):

    # just write the limit to a file. to activate, call set_tc_class

    tc_path = os.path.join(cfg.VAR_DB_OPENVPS, 'tc', vserver)

    n, ceil = None, limit
    if os.path.exists(tc_path):
       # read them in 
       parts  = open(tc_path).read().strip().split(':')
       if len(parts) > 1:
           n = parts[1]

    # write it
    if n:
        open(tc_path, 'w').write('%s:%s' % (ceil, n))
    else:
        open(tc_path, 'w').write('%s' % ceil)
    print 'wrote', ceil, tc_path

    # is there a cap?
    if cap:
        tc_path = os.path.join(cfg.VAR_DB_OPENVPS, 'tc', vserver+'-CAP')
        open(tc_path, 'w').write('%s' % cap)


def get_bwlimit(vserver):

    # return tuple (limit, cap)

    tc_path = os.path.join(cfg.VAR_DB_OPENVPS, 'tc', vserver)

    limit = None
    if os.path.exists(tc_path):

       parts  = open(tc_path).read().strip().split(':')
       if len(parts) == 1:
           limit = parts[0]
       else:
           limit, n = parts[:2]

    # is there a cap? a cap a "shadow" overriding limit not visible to the VPS user.
    cap_path = os.path.join(cfg.VAR_DB_OPENVPS, 'tc', vserver+'-CAP')

    cap = None
    if os.path.exists(cap_path):
        cap = open(cap_path).read().strip()

    return limit, cap


def fw_get_config(vserver):

    # read fw configuration

    config = {}
    
    fw_path = os.path.join(cfg.VAR_DB_OPENVPS, 'fw', vserver)
    locals = {}
    if os.path.exists(fw_path):
        execfile(fw_path, {}, locals)

    if locals.has_key('FW'):
        config = locals['FW']

    if not config.has_key('CURRENT'):
        config['CURRENT'] = {'mode': 'allow', 'open':[], 'close':[]}

    if not config.has_key('NEXT'):
        config['NEXT'] = {'mode': 'allow', 'open':[], 'close':[]}

    if not config.has_key('BLOCK'):
        config['BLOCK'] = []

    return config

def fw_save_config(vserver, config):

    # make sure the directory exists
    fw_dir = os.path.join(cfg.VAR_DB_OPENVPS, 'fw')
    if not os.path.exists(fw_dir):
        os.mkdir(fw_dir)

    s = '# Saved by vsutil.py:fw_save_config() on %s\n\n' % time.ctime()
    try:
        s += 'FW = ' + pprint.pformat(config, width=80)
    except:
        # python 2.3?
        s += 'FW = ' + pprint.pformat(config)
    s += '\n'

    fw_path = os.path.join(fw_dir, vserver)
    open(fw_path, 'w').write(s)

def fw_start(vserver, mode):

    # just save. rules are generated at the end)

    config = fw_get_config(vserver)
    config['NEXT'] = {'mode': mode, 'open':[], 'close':[]}
    fw_save_config(vserver, config)

def fw_open(vserver, proto, port, ips):

    # just save. rules are generated at the end)

    config = fw_get_config(vserver)
    rules = config['NEXT']['open']
    rules.append((proto, port, ips))

    fw_save_config(vserver, config)

    
def fw_close(vserver, proto, port, ips):

    # just save. rules are generated at the end)

    config = fw_get_config(vserver)
    rules = config['NEXT']['close']
    rules.append((proto, port, ips))

    fw_save_config(vserver, config)

def fw_block(vserver, ips):

    for ip in ips:
        cmd = "/sbin/iptables -A ov_%s_block -s %s -j REJECT" % (vserver, ip)
        print cmd
        err = commands.getoutput(cmd)
        if err: print err

    # add it to config
    config = fw_get_config(vserver)

    for ip in ips:
        config['BLOCK'].append(ip)

    fw_save_config(vserver, config)

def fw_clear_block(vserver):

    # clear the block list

    cmd = "/sbin/iptables -F ov_%s_block" % vserver
    print cmd
    err = commands.getoutput(cmd)
    if err: print err

    config = fw_get_config(vserver)
    config['BLOCK'] = []
    fw_save_config(vserver, config)

def fw_setup(vserver, config=None):

    # generate and execute iptables rules from the given config
    # if no config given, default to 'CURRENT'

    # make sure the chains exist
    iptables_rules(vserver)

    chain_name = 'ov_' + vserver

    if config is None:
        config = fw_get_config(vserver)['CURRENT']

    # clear the chain
    cmd = '/sbin/iptables -F %s' % chain_name
    print cmd
    err = commands.getoutput(cmd)
    if err: print err

    # XXX hack begin
    if err and 'No chain' in err:
        print 'Trying again...'
        cmd = '/sbin/iptables -N %s' % chain_name
        print cmd
        err = commands.getoutput(cmd)
        if err: print err
        cmd = '/sbin/iptables -F %s' % chain_name
        print cmd
        err = commands.getoutput(cmd)
        if err: print err
    # XXX hack end

    if config['mode'] == 'block':

        # established connections OK
        #cmd = '/sbin/iptables -A %s -m state --state "ESTABLISHED,RELATED" -j ACCEPT' % \
        #      chain_name
        cmd = '/sbin/iptables -A %s -m conntrack --ctstate "ESTABLISHED,RELATED" -j ACCEPT' % \
              chain_name
        print cmd
        err = commands.getoutput(cmd)
        if err: print err

        for rule in config['open']:
            proto, port, ips = rule

            if ips:
                for ip in ips:
                    cmd = '/sbin/iptables -A %s -p %s --dport %d -s %s -j ACCEPT' % \
                          (chain_name, proto, port, ip)
                    print cmd
                    err = commands.getoutput(cmd)
                    if err: print err
            else:
                cmd = '/sbin/iptables -A %s -p %s --dport %d -j ACCEPT' % \
                      (chain_name, proto, port)
                print cmd
                err = commands.getoutput(cmd)
                if err: print err

        # Allow ICMP
        for c in [
            '/sbin/iptables -A %s -p icmp --icmp-type destination-unreachable -j ACCEPT',
            '/sbin/iptables -A %s -p icmp --icmp-type time-exceeded -j ACCEPT',
            '/sbin/iptables -A %s -p icmp --icmp-type echo-request -j ACCEPT',
            '/sbin/iptables -A %s -p icmp --icmp-type echo-reply -j ACCEPT',
            ]:
            cmd = c % chain_name
            print cmd
            err = commands.getoutput(cmd)
            if err: print err
            
        # last rule is block
        cmd = '/sbin/iptables -A %s -j REJECT' % chain_name
        print cmd
        err = commands.getoutput(cmd)
        if err: print err

    else:
        # mode is allow

        for rule in config['close']:
            proto, port, ips = rule

            if ips:
                # reject from these IPs
                for ip in ips:
                    cmd = '/sbin/iptables -A %s -p %s --dport %d -s %s -j REJECT' % \
                          (chain_name, proto, port, ip)
                    print cmd
                    err = commands.getoutput(cmd)
                    if err: print err
            else:
            # block outright
                cmd = '/sbin/iptables -A %s -p %s --dport %d -j REJECT' % \
                      (chain_name, proto, port)
                print cmd
                err = commands.getoutput(cmd)
                if err: print err


def fw_finish(vserver):

    # generate and execute iptables rules from the NEXT config,
    # then save NEXT as current

    config = fw_get_config(vserver)
    next = config['NEXT']

    fw_setup(vserver, next)

    config['PREV'] = config['CURRENT']
    config['CURRENT'] = next
    del config['NEXT']

    fw_save_config(vserver, config)

def _ipt_init():
    
##     cmd = 'modprobe ipt_REJECT'
##     print cmd
##     err = commands.getoutput(cmd)
##     if err: print err

##     cmd = 'modprobe xt_tcpudp'
##     print cmd
##     err = commands.getoutput(cmd)
##     if err: print err

##     cmd = 'modprobe xt_conntrack'
##     print cmd
##     err = commands.getoutput(cmd)
##     if err: print err

##     cmd = 'modprobe ip_conntrack'
##     print cmd
##     err = commands.getoutput(cmd)
##     if err: print err

    # do the actions we expect to do on a dummy chain -
    # this seems to load all the right modules

    cmd = '/sbin/iptables -N _ipt_init'
    print cmd
    err = commands.getoutput(cmd)
    if err: print err
    cmd = '/sbin/iptables -F _ipt_init'
    print cmd
    err = commands.getoutput(cmd)
    if err: print err
    cmd = '/sbin/iptables -A _ipt_init -m conntrack --ctstate "ESTABLISHED,RELATED" -j ACCEPT'
    print cmd
    err = commands.getoutput(cmd)
    if err: print err
    cmd = '/sbin/iptables -A _ipt_init -p tcp --dport 22 -s 172.17.17.17 -j ACCEPT'
    print cmd
    err = commands.getoutput(cmd)
    if err: print err    
    cmd = '/sbin/iptables -A _ipt_init -p icmp --icmp-type destination-unreachable -j ACCEPT'
    print cmd
    err = commands.getoutput(cmd)
    if err: print err    
    cmd = '/sbin/iptables -A _ipt_init -p icmp --icmp-type time-exceeded -j ACCEPT'
    print cmd
    err = commands.getoutput(cmd)
    if err: print err    
    cmd = '/sbin/iptables -A _ipt_init -p icmp --icmp-type echo-request -j ACCEPT'
    print cmd
    err = commands.getoutput(cmd)
    if err: print err    
    cmd = '/sbin/iptables -A _ipt_init -p icmp --icmp-type echo-reply -j ACCEPT'
    print cmd
    err = commands.getoutput(cmd)
    if err: print err    
    cmd = '/sbin/iptables -A _ipt_init -j REJECT'
    print cmd
    err = commands.getoutput(cmd)
    if err: print err    
