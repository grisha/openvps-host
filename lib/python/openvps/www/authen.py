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

# $Id: authen.py,v 1.1 2005/01/12 21:24:43 grisha Exp $

""" Authentication handler for the panel. This
requires mod_python 3.1 or later """

from mod_python import apache

import os

from openvs.host import vsutil

def authenhandler(req):

    # a userid matching the vserver name must exist in the vserver

    path = os.path.normpath(req.uri)
    userid = path.split('/')[1]

    vservers = vsutil.list_vservers()

    passwd = req.get_basic_auth_pw()
    vserver = userid

    if vservers.has_key(userid):
        if vsutil.check_passwd(vserver, userid, passwd):
            return apache.OK
        else:
            return apache.HTTP_UNAUTHORIZED
    else:
        return apache.HTTP_FORBIDDEN

