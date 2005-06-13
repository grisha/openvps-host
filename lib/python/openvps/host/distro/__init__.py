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

# $Id: __init__.py,v 1.2 2005/06/13 21:14:54 grisha Exp $

import os

# create an __all__ that lists all the module files in this directory
# except for util. util will be doing an import * to give every module
# an opportunity to register. With this mechanism in place, a new
# distribution could just drop in a .py file which defines a class
# suitable for their distro.

__all__ = []

files = os.listdir(__path__[0])
for file in files:
    if file.endswith('.py') and file != 'distro_util.py':
        __all__.append(file[:-3])



                 


