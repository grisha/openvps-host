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

# $Id: authen.py,v 1.6 2005/02/05 05:26:36 grisha Exp $

""" Authentication handler for the panel. This
requires mod_python 3.1 or later """

from mod_python import apache

import os

from openvps.host import vsutil

def authenhandler(req):

    # a userid matching the vserver name must exist in the vserver

    passwd = req.get_basic_auth_pw()
    userid = req.user
    
    path = os.path.normpath(req.uri)
    parts = path.split('/', 3)

    if len(parts) < 2:
        return apache.HTTP_FORBIDDEN

    if parts[1] == 'admin':

        # new style
        if len(parts) < 3:
            return apache.HTTP_FORBIDDEN
        vserver_name = parts[2]

    elif parts[1] == 'pubkey':

        # no authen
        return apache.OK

    else:

        # old style, XXX remove soon
        vserver_name = path.split('/')[1]

    vservers = vsutil.list_vservers()

    if vservers.has_key(vserver_name):
        
        if vsutil.check_passwd(vserver_name, userid, passwd):
            return apache.OK
        else:
            return apache.HTTP_UNAUTHORIZED
    else:
        return apache.HTTP_FORBIDDEN

