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

# $Id: vsutil.py,v 1.4 2004/05/25 17:17:44 grisha Exp $

""" Vserver-specific functions """

import os
import commands
import struct
import fcntl

import cfg

from oh.common import util

def is_vserver_kernel():
    """ Are we running on a VServer kernel? """

    kinfo = commands.getoutput('/bin/uname -a').split()[2]
    return '-vs' in kinfo

def list_vservers():
    """ Return a dictionary of vservers """

    result = {}

    for file in os.listdir(cfg.ETC_VSERVERS):
        if not file.endswith('.conf'):
            # not a config file
            continue

        params = {}

        for line in open(os.path.join(cfg.ETC_VSERVERS, file)):

            if not line.strip() or line.strip().startswith('#'):
                # it's a comment
                continue

            key, val = line.strip().split('=')
            if val.startswith('"') and val.endswith('"'):
                val = val[1:-1]

            params[key] = val

        # what is our name
        name = file[:-len('.conf')]

        # add some convenience parameters
        params['name'] = name
        params['root'] = os.path.join(cfg.VSERVERS_ROOT, name)
            
        result[name] = params

    return result

def get_vserver_info_by_ip(ip):

    """ get vserver information based on ip """

    vservers = list_vservers()

    result = None
    for vserver in vservers:
        if vservers[vserver]['IPROOT'] == ip:
            result = vservers[vserver]

    return result

def guess_vserver_device():
    """ Guess which device is the one mounting our vservers partition """

    s = commands.getoutput('/bin/mount | /bin/grep tagctx | /usr/bin/head -n 1')
    device = s.split()[0]

    return device

def running_vservers():

    result = {}

    s = commands.getoutput(cfg.VSERVER_STAT)

    lines = s.splitlines()
    for line in lines:

        fields = line.split()
        if fields[0] in ['CTX', '0']:
            continue

        xid, name = fields[0], fields[7]
        result[xid] = name
        
    return result

def check_passwd(vserver, userid, passwd):
    """ Check password for a user on a vserver """

    vpath = os.path.join(cfg.VSERVERS_ROOT, vserver)

    cmd = '%s %s' % (cfg.OHCHKPWD, vpath)
    pipe = os.popen(cmd, 'w')
    pipe.write('%s:%s' % (userid, passwd))
    sts = pipe.close()
               
    return not sts

def read_shadow(vserver):
    """ Read shadow file """

    users = {}
    
    shadow = os.path.join(cfg.VSERVERS_ROOT, 'etc', 'shadow')
    for line in open(shadow):
        uid, pwhash = line.split(':', 2)
        users[uid] = pwhash
        
    return users

def is_file_immutable_link(path):
    """ Does this file have immutable_file and immutable_link
        flags set, which would mean it is a safe bet that it
        cannot be modified from within a vserver """

    ## this should really be
    # EXT2_IOC_GETFLAGS = 0x80046601
    # but because of a FutureWarnig for 2.4, we have this
    EXT2_IOC_GETFLAGS = struct.unpack('i',
                                      struct.pack('L', 0x80046601L))[0]

    f = open(path)
    flags = struct.unpack('L',
                          fcntl.ioctl(f.fileno(),
                                      EXT2_IOC_GETFLAGS, '    '))[0]
    
    # 0x00008010 is EXT2_IMMUTABLE_FILE_FL | EXT2_IMMUTABLE_LINK_FL
    return flags & 0x00008010 == 0x00008010

def set_file_immutable_link(path):
    """ Sets the ext2 immutable flag. This is the special
        flag that only exists in a vserver kernel."""

    f = open(path)
    # 0x00008010 is EXT2_IMMUTABLE_FILE_FL | EXT2_IMMUTABLE_LINK_FL
    rec = struct.pack('L', 0x00008010)
    # 0x40046602 is EXT2_IOC_SETFLAGS
    fcntl.ioctl(f.fileno(), 0x40046602, rec)

