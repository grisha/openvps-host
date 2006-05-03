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

# $Id: vsutil.py,v 1.17 2006/05/03 20:13:39 grisha Exp $

""" Vserver-specific functions """

import os
import commands
import struct
import fcntl
import sys
import tempfile

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

def save_vserver_config(name, ip, xid, hostname=None, dev='eth0'):

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

def check_passwd(vserver, userid, passwd):
    """ Check password for a user on a vserver """

    if vserver == '/':
        # this is actual host machine
        vpath = '/'
    else:
        vpath = os.path.join(cfg.VSERVERS_ROOT, vserver)

    cmd = '%s %s' % (cfg.OVCHKPWD, vpath)
    pipe = os.popen(cmd, 'w')
    pipe.write('%s:%s' % (userid, passwd))
    sts = pipe.close()
               
    return not sts

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


def iptables_rules(vserver):

    print 'Adding iptables rules for bandwidth montoring'

    # get vserver IPs
    ips = [x['ip'] for x in get_vserver_config(vserver)['interfaces']]

    for ip in ips:

        # does the rule exist?
        cmd = 'iptables -L INPUT -n | grep %s' % ip
        if not commands.getoutput(cmd):

            #cmd = 'iptables -D INPUT -i %s -d %s' % (cfg.DFT_DEVICE, ip)
            #print ' ', cmd
            #commands.getoutput(cmd)
            cmd = 'iptables -A INPUT -i %s -d %s' % (cfg.DFT_DEVICE, ip)
            print ' ', cmd
            commands.getoutput(cmd)

        else:
            print 'INPUT rules already exists for %s, skipping' % ip
            
        # does the rule exist?
        cmd = 'iptables -L OUTPUT -n | grep %s' % ip
        if not commands.getoutput(cmd):
            
            #cmd = 'iptables -D OUTPUT -o %s -s %s' % (cfg.DFT_DEVICE, ip)
            #print ' ', cmd
            #commands.getoutput(cmd)
            cmd = 'iptables -A OUTPUT -o %s -s %s' % (cfg.DFT_DEVICE, ip)
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
        s = commands.getoutput(cmd)
        
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
                print '   ', cmd
                s = commands.getoutput(cmd)
                if s:
                    print s

        # is there a classes ?

        cmd = '/sbin/tc class ls dev %s parent 10:2 | grep "htb 10:%s"' % (cfg.DFT_DEVICE, n)
        s = commands.getoutput(cmd)

        if 'class' in s:

            # kill it too
            cmd = '/sbin/tc class del dev %s parent 10:2 classid 10:%s' % (cfg.DFT_DEVICE, n)
            print '   ', cmd
            s = commands.getoutput(cmd)
            if s:
                print s

        # now we can do our thing

        cmd = '/sbin/tc class add dev %s parent 10:2 classid 10:%s htb rate %s ceil %s burst 15k' % \
              (cfg.DFT_DEVICE, n, cfg.DFT_VS_RATE, ceil)
        print '   ', cmd
        s = commands.getoutput(cmd)
        if s:
            print s

        U32 = '/sbin/tc filter add dev %s protocol ip parent 10:0 prio 1 u32' % cfg.DFT_DEVICE
        
        for i in vs[vserver]['interfaces']:
            if i['dev'] == cfg.DFT_DEVICE or i['dev'].startswith('dummy'):

                # dummy is here because its packets actually enter via DFT_DEVICE in
                # a DSR load-balancing scenario
                
                cmd = '%s match ip src %s/32 flowid 10:%s' % (U32, i['ip'], n)
                print '   ', cmd
                s = commands.getoutput(cmd)
                if s:
                    print s


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
