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

# XXX This file may need to be GPL'd

# $Id: setup.py,v 1.1 2004/11/07 05:11:10 grisha Exp $

from distutils.core import setup, Extension

import os

setup(name="vspython",
      version="0.01",
      description="Linux VServer API",
      author="OpenVPS Project",
      author_email="dev@openvps.org",
      url="http://www.openvps.org/",
      py_modules=['vserver'],
      ext_modules=[Extension("_vserver",
                             ["_vserver.c"],
                             include_dirs=['.'],
                             define_macros=[('HAVE_CONFIG_H', None)],
                             libraries=['vserver'],
                             )
                   ]
      )

# makes emacs go into python mode
### Local Variables:
### mode:python
### End:
