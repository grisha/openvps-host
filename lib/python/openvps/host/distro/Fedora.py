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

# $Id: Fedora.py,v 1.1 2005/06/08 20:49:38 grisha Exp $

# This is the base class for Fedora Core distributions.

from RedHat import RedHat
import util

class Fedora_Core(RedHat):

    FC_VER = 0

    def distro_version(self):

        rh_ver = RedHat.distro_version(self)
        if rh_ver:
            fc_ver = rh_ver['name'].split()[-1]
            if int(fc_ver) == self.FC_VER:
                return self.FC_VER

class Fedora_Core_1(Fedora_Core):

    FC_VER = 1

util.register(Fedora_Core_1)

class Fedora_Core_2(Fedora_Core):

    FC_VER = 2

util.register(Fedora_Core_2)

class Fedora_Core_3(Fedora_Core):

    FC_VER = 3

util.register(Fedora_Core_3)

