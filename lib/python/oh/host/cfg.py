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

# $Id: cfg.py,v 1.1 2004/03/25 16:48:40 grisha Exp $

""" This module contains our configuration """

import os
import time
import pprint
import re

def load_file(path):
    """Load a config file"""

    locals = {}

    try:
        execfile(path, {}, locals)
    except IOError, err:
        if 'No such file' in str(err):
            # no file is OK
            pass
        else:
            raise sys.exc_info()[0], sys.exc_info()[1], sys.exc_info()[2]

    return locals

def save_file(path, data):
    """Save configuration in a config file.
    (Completely wipes the file)
    XXX - There is no way to insert comments into this file.
    """

    login = ''
    if hasattr(os, 'getlogin'):
        login = 'by ' + os.getlogin()

    banner = "\n# WARNING! This file was autogenerated on %s %s\n\n" \
             % (time.ctime(), login)

    pp = pprint.PrettyPrinter(indent=4)
    s = pp.pformat(data)

    open(path, 'w').write(banner + s)


# compile CLONE_RULES

def compile_clone_rules(rules):
    """ Get the clone rules from the config and compile into a regexp """ 

    copy_exp, touch_exp, skip_exp = None, None, None

    # this replaces starting slash with '^/', then joins with '|'
    # XXX this needs to be in like load_config or smth
    if rules['copy']:
        copy_exp = '|'.join([re.sub('^/', '^/', x) for x in rules['copy']])
        copy_exp = re.compile(copy_exp)
    if rules['touch']:
        touch_exp = '|'.join([re.sub('^/', '^/', x) for x in rules['touch']])
        touch_exp = re.compile(touch_exp)
    if rules['skip']:
        skip_exp = '|'.join([re.sub('^/', '^/', x) for x in rules['skip']])
        skip_exp = re.compile(skip_exp)

    return copy_exp, touch_exp, skip_exp

# This is where the default config is read
# and overlayed by the config in the config_file

from dft import *
locals().update(load_file(CONFIG_FILE))

# replace CLONE_RULES with a compiled version,
# the result should be a tuple of (copy, touch, skip)
# re objects.

CLONE_RULES = compile_clone_rules(CLONE_RULES)



