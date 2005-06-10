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

# $Id: util.py,v 1.3 2005/06/10 03:09:21 grisha Exp $

# this module contains a register function that gives an opportunity
# for distro modules in this package to register their
# distribution-specific class instance.

_registered = []

def register(distro_class, vps_class):
    _registered.append((distro_class, vps_class))

# this should trigger the registrations
from distro import *

def probe_distro(distroot):

    # give me a url (or a file path) and will tell you if
    # I recognize this distro by returning an instance of the
    # appropriate distro class

    for distro_class, vps_class in _registered:

        dist = distro_class(distroot)
        version = dist.distro_version()
        if version:
            # got it!
            return dist

def probe_vps(refroot):

    # guess by looking at an already installed system

    for distro_class, vps_class in _registered:

        vps = vps_class(refroot)
        version = vps.distro_version()
        if version:
            # got it!
            return vps
        
    
