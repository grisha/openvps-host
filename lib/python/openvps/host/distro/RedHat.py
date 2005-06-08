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

# $Id: RedHat.py,v 1.1 2005/06/08 20:49:38 grisha Exp $

# This is the base class for RedHat (or RedHat-like?) distros.

from Distro import Distro 
import os
import time

class RedHat(Distro):

    def distro_version(self):

        # is this a redhat distribution?

        discinfo = self.read('.discinfo')

        lines = discinfo.splitlines()[:4]

        if len(lines) < 4:
            # wrong file
            return None

        result = {}
        
        try:
            result['buildtime'] = time.localtime(float(lines[0].strip()))
            result['name'] = lines[1].strip()
            result['platform'] = lines[2]
            # this is a comma-separated list of cd's provided here
            result['volumes'] = lines[3]
        except "BLAH":
            return None

        return result
