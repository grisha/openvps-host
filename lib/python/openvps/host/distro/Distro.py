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

# $Id: Distro.py,v 1.1 2005/06/08 20:49:38 grisha Exp $

# this is the base object for all distributions, it should only contain
# methods specific to _any_ distribution

import urllib
import os

class Distro(object):

    def __init__(self, url):

        # the url is where the distribution is located
        self.distroot = url


    def read(self, relpath):

        # read a path relative to the url
        try:
            return urllib.urlopen(os.path.join(self.distroot, relpath)).read()
        except IOError:
            return None
                                  

        

