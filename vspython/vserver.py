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

# $Id: vserver.py,v 1.3 2006/07/08 19:21:24 grisha Exp $

import _vserver

from exceptions import ValueError


VC_SAMECTX                      = -2
VC_DYNAMIC_XID                  = -1

VC_CAP_CHOWN            	= 0
VC_CAP_DAC_OVERRIDE     	= 1
VC_CAP_DAC_READ_SEARCH  	= 2
VC_CAP_FOWNER           	= 3
VC_CAP_FSETID           	= 4
VC_CAP_KILL             	= 5
VC_CAP_SETGID           	= 6
VC_CAP_SETUID           	= 7
VC_CAP_SETPCAP          	= 8
VC_CAP_LINUX_IMMUTABLE  	= 9
VC_CAP_NET_BIND_SERVICE 	= 10
VC_CAP_NET_BROADCAST    	= 11
VC_CAP_NET_ADMIN        	= 12
VC_CAP_NET_RAW          	= 13
VC_CAP_IPC_LOCK         	= 14
VC_CAP_IPC_OWNER        	= 15
VC_CAP_SYS_MODULE       	= 16
VC_CAP_SYS_RAWIO        	= 17
VC_CAP_SYS_CHROOT       	= 18
VC_CAP_SYS_PTRACE       	= 19
VC_CAP_SYS_PACCT        	= 20
VC_CAP_SYS_ADMIN        	= 21
VC_CAP_SYS_BOOT         	= 22
VC_CAP_SYS_NICE         	= 23
VC_CAP_SYS_RESOURCE     	= 24
VC_CAP_SYS_TIME 		= 25
VC_CAP_SYS_TTY_CONFIG   	= 26
VC_CAP_MKNOD            	= 27
VC_CAP_LEASE            	= 28
VC_CAP_QUOTACTL          	= 29

VC_VXF_INFO_LOCK		= 0x00000001
VC_VXF_INFO_NPROC		= 0x00000004
VC_VXF_INFO_PRIVATE		= 0x00000008
VC_VXF_INFO_INIT		= 0x00000010

VC_VXF_INFO_HIDEINFO		= 0x00000020
VC_VXF_INFO_ULIMIT		= 0x00000040
VC_VXF_INFO_NAMESPACE		= 0x00000080

VC_VXF_SCHED_HARD		= 0x00000100
VC_VXF_SCHED_PRIO		= 0x00000200
VC_VXF_SCHED_PAUSE		= 0x00000400

VC_VXF_VIRT_MEM			= 0x00010000
VC_VXF_VIRT_UPTIME		= 0x00020000
VC_VXF_VIRT_CPU			= 0x00040000

VC_VXF_HIDE_MOUNT		= 0x01000000
VC_VXF_HIDE_NETIF		= 0x02000000

VC_VXF_STATE_SETUP		= (1L<<32)
VC_VXF_STATE_INIT		= (1L<<33)

VC_VXC_SET_UTSNAME              = 0x00000001
VC_VXC_SET_RLIMIT               = 0x00000002

VC_VXC_ICMP_PING                = 0x00000100

VC_VXC_SECURE_MOUNT             = 0x00010000

VC_VXSM_FILL_RATE               = 0x0001
VC_VXSM_INTERVAL                = 0x0002
VC_VXSM_TOKENS                  = 0x0010
VC_VXSM_TOKENS_MIN              = 0x0020
VC_VXSM_TOKENS_MAX              = 0x0040
VC_VXSM_PRIO_BIAS               = 0x0100


VC_IATTR_XID                    = 0x01000000

VC_IATTR_ADMIN                  = 0x00000001
VC_IATTR_WATCH                  = 0x00000002
VC_IATTR_HIDE                   = 0x00000004
VC_IATTR_FLAGS                  = 0x00000007

VC_IATTR_BARRIER                = 0x00010000
VC_IATTR_IUNLINK                = 0x00020000
VC_IATTR_IMMUTABLE              = 0x00040000


def get_version():
    return _vserver.vc_get_version()

#def change_context(xid=VC_SAMECTX, remove_cap=0, flags=0):
#    return _vserver.vc_new_s_context(xid, remove_cap, flags)

def get_file_xid(name):
    return _vserver.vc_get_iattr(name)[0]


iattr_xref = {VC_IATTR_XID       : 'xid',
              VC_IATTR_ADMIN     : 'admin',
              VC_IATTR_WATCH     : 'watch',
              VC_IATTR_HIDE      : 'hide',
              VC_IATTR_BARRIER   : 'barrier',
              VC_IATTR_IUNLINK   : 'iunlink',
              VC_IATTR_IMMUTABLE : 'immutable'}

def get_file_attr(name):
    
    xid, flags, mask =  _vserver.vc_get_iattr(name)

    result = {}

    for flag in [VC_IATTR_XID, VC_IATTR_ADMIN,
                 VC_IATTR_WATCH, VC_IATTR_HIDE,
                 VC_IATTR_BARRIER, VC_IATTR_IUNLINK,
                 VC_IATTR_IMMUTABLE]:

        flag_name = iattr_xref[flag]
        result[flag_name] = not not (flag & mask & flags)

    return result

def set_file_attr(name, flags, xid=None):

    if xid is None:
        _xid = 0
    else:
        _xid = xid

    _flags = 0
    _mask = 0

    for flag in [VC_IATTR_XID, VC_IATTR_ADMIN,
                 VC_IATTR_WATCH, VC_IATTR_HIDE,
                 VC_IATTR_BARRIER, VC_IATTR_IUNLINK,
                 VC_IATTR_IMMUTABLE]:

        flag_name = iattr_xref[flag]
        
        if flags.has_key(flag_name):

            _mask = _mask | flag
            if flags[flag_name]:
                _flags = _flags | flag
            else:
                _flags = _flags & ~flag

    return _vserver.vc_set_iattr(name, _xid, _flags, _mask)

def set_file_xid(name, xid):

    return _vserver.vc_set_iattr(name, xid, 0, VC_IATTR_XID)
    
