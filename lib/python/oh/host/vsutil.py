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

# $Id: vsutil.py,v 1.8 2004/10/12 18:34:27 grisha Exp $

""" Vserver-specific functions """

import os
import commands
import struct
import fcntl
import sys

import cfg

from oh.common import util

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
    # is because the sematics of each parameter are to complex to be generic, e.g.
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

    # uts
    os.mkdir(os.path.join(dirname, 'uts'))

    # nodename
    open(os.path.join(dirname, 'uts', 'nodename'), 'w').write(hostname+'\n')

    # nice
    open(os.path.join(dirname, 'nice'), 'w').write(cfg.DFT_NICE+'\n')

    # run
    os.symlink('/var/run/vservers/%s' % name, os.path.join(dirname, 'run'))

    # run.rev
    os.symlink(os.path.join(cfg.ETC_VSERVERS, '.defaults/run.rev'), os.path.join(dirname, 'run.rev'))

    # vdir
    root = os.path.join(cfg.VSERVERS_ROOT, name)
    os.symlink(root, os.path.join(dirname, 'vdir'))

    # interfaces
    os.mkdir(os.path.join(dirname, 'interfaces'))

    # interface 0
    os.mkdir(os.path.join(dirname, 'interfaces', '0'))

    # interface 0 ip
    open(os.path.join(dirname, 'interfaces', '0', 'ip'), 'w').write(ip+'\n')

    # interface 0 mask (yes, it *must* be /32, or they will end up grouped)
    open(os.path.join(dirname, 'interfaces', '0', 'mask'), 'w').write('255.255.255.255\n')

    # interface 0 name
    open(os.path.join(dirname, 'interfaces', '0', 'name'), 'w').write(name+'\n')

    # interface 0 dev
    open(os.path.join(dirname, 'interfaces', '0', 'dev'), 'w').write(cfg.DFT_DEVICE+'\n')

    # fstab
    open(os.path.join(dirname, 'fstab'), 'w').writelines([
        'none                    /dev/pts                devpts  gid=5,mode=620  0 0\n'
        'none                    /proc                   proc    defaults        0 0\n'])

    # apps/init/mark (this makes the vserver start at startup by vservers-default)
    os.mkdir(os.path.join(dirname, 'apps'))
    os.mkdir(os.path.join(dirname, 'apps', 'init'))
    open(os.path.join(dirname, 'apps', 'init', 'mark'), 'w').write('default\n')

    print 'Done'


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

## XXX this does not appear to be used anywhere
# def get_vserver_info_by_ip(ip):

#     """ get vserver information based on ip """

#     vservers = list_vservers()

#     result = None
#     for vserver in vservers:
#         if vservers[vserver]['IPROOT'] == ip:
#             result = vservers[vserver]

#     return result

def guess_vserver_device():
    """ Guess which device is the one mounting our vservers partition """

    s = commands.getoutput('/bin/mount | /bin/grep tagxid | /usr/bin/head -n 1')
    device = s.split()[0]

    return device

## XXX does not appear to be used
# def running_vservers():

#     result = {}

#     s = commands.getoutput(cfg.VSERVER_STAT)

#     lines = s.splitlines()
#     for line in lines:

#         fields = line.split()
#         if fields[0] in ['CTX', '0']:
#             continue

#         xid, name = fields[0], fields[7]
#         result[xid] = name
        
#     return result

def check_passwd(vserver, userid, passwd):
    """ Check password for a user on a vserver """

    vpath = os.path.join(cfg.VSERVERS_ROOT, vserver)

    cmd = '%s %s' % (cfg.OHCHKPWD, vpath)
    pipe = os.popen(cmd, 'w')
    pipe.write('%s:%s' % (userid, passwd))
    sts = pipe.close()
               
    return not sts

## XXX does not appear to be used
# def read_shadow(vserver):
#     """ Read shadow file """

#     users = {}
    
#     shadow = os.path.join(cfg.VSERVERS_ROOT, 'etc', 'shadow')
#     for line in open(shadow):
#         uid, pwhash = line.split(':', 2)
#         users[uid] = pwhash
        
#     return users

def set_file_immutable_unlink(path):
    """ Sets the ext2 immutable-unlink flag. This is the special
        flag that only exists in a vserver kernel."""

    # unfortunately this can only be done via command-line
    # XXX unless we make a python binding for vserver, that is.

    cmd = "setattr --iunlink '%s'" % path
    s, o = commands.getstatusoutput(cmd)
    if s:
        print s
        raise 'Error running %s' % `cmd`

def is_file_immutable_unlink(path):
    """ Check wither the iunlink flag is set """

    cmd = "showattr '%s'" % path
    s, o = commands.getstatusoutput(cmd)
    if s:
        print s
        raise 'Error running %s' % `cmd`
    return o[4:6] == 'UI'

#
# XXX These are obsolete with vs 1.9.x and up
#

# def set_file_immutable_link_legacy(path):
#     """ Sets the ext2 immutable flag. This is the special
#         flag that only exists in a vserver kernel."""

#     f = open(path)
#     # 0x00008010 is EXT2_IMMUTABLE_FILE_FL | EXT2_IMMUTABLE_LINK_FL
#     rec = struct.pack('L', 0x00008010)
#     # 0x40046602 is EXT2_IOC_SETFLAGS
#     fcntl.ioctl(f.fileno(), 0x40046602, rec)

# def is_file_immutable_link_legacy(path):
#     """ Does this file have immutable_file and immutable_link
#         flags set, which would mean it is a safe bet that it
#         cannot be modified from within a vserver """

#     ## this should really be
#     # EXT2_IOC_GETFLAGS = 0x80046601
#     # but because of a FutureWarnig for 2.4, we have this
#     EXT2_IOC_GETFLAGS = struct.unpack('i',
#                                       struct.pack('L', 0x80046601L))[0]

#     f = open(path)
#     flags = struct.unpack('L',
#                           fcntl.ioctl(f.fileno(),
#                                       EXT2_IOC_GETFLAGS, '    '))[0]
    
#     # 0x00008010 is EXT2_IMMUTABLE_FILE_FL | EXT2_IMMUTABLE_LINK_FL
#     return flags & 0x00008010 == 0x00008010

