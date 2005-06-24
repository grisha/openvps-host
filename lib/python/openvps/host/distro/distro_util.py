#
# Copyright 2005 OpenHosting, Inc.
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

# $Id: distro_util.py,v 1.2 2005/06/24 17:55:43 grisha Exp $

# this module contains a register function that gives an opportunity
# for distro modules in this package to register their
# distribution-specific class instance.

_registered = []

def register(klass):
    _registered.append(klass)

# this should trigger the registrations
try:
    from openvps.host.distro import *
except AttributeError:
    
    # not sure what the problem is, but this will fail depending on
    # how the module is imported.
    print 'WARNING: Registrations probably failed. Make sure distro_util is import like this:'
    print 'from openvps.host.distro import distro_util'


def probe_distro(vpsroot, distroot):

    # give me a url (or a file path) and will tell you if
    # I recognize this distro by returning an instance of the
    # appropriate distro class

    for klass in _registered:

        dist = klass(vpsroot, distroot)
        version = dist.distro_version()
        if version:
            # got it!
            return dist

def probe_vps(vpsroot):

    # guess by looking at an already installed system

    for klass in _registered:

        vps = klass(vpsroot)
        version = vps.vps_version()
        if version:
            # got it!
            return vps
        
    
