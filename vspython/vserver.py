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

# $Id: vserver.py,v 1.1 2004/11/07 05:11:10 grisha Exp $

import _vserver

from exceptions import ValueError

# iattr constants

VC_IATTR_XID                    = 0x01000000

VC_IATTR_ADMIN                  = 0x00000001
VC_IATTR_WATCH                  = 0x00000002
VC_IATTR_HIDE                   = 0x00000004
VC_IATTR_FLAGS                  = 0x00000007

VC_IATTR_BARRIER                = 0x00010000
VC_IATTR_IUNLINK                = 0x00020000
VC_IATTR_IMMUTABLE              = 0x00040000



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
    
