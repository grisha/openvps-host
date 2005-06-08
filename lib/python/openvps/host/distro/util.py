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

# $Id: util.py,v 1.1 2005/06/08 20:49:38 grisha Exp $

# this module contains a register function that gives an opportunity
# for distro modules in this package to register their
# distribution-specific class instance.

_registered = []

def register(obj):
    _registered.append(obj)

# this should trigger the registrations
from distro import *

def get_distros():
    return _registered

def probe_distro(distroot):

    # give me a url (or a file path) and will tell you if
    # I recognize this distro by returning an instance of the
    # appropriate distro class

    for Class in _registered:

        dist = Class(distroot)
        version = dist.distro_version()
        if version:
            # got it!
            return dist
