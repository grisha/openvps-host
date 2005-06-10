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

# $Id: Distro.py,v 1.4 2005/06/10 21:36:59 grisha Exp $

# this is the base object for all distributions, it should only contain
# methods specific to _any_ distribution

import urllib
import os
import commands
import stat

class Distro(object):

    def __init__(self, vpsroot, url=None):

        if vpsroot:
            self.vpsroot = os.path.abspath(vpsroot)
        else:
            self.vpsroot = None

        # the url is where the distribution is located
        self.distroot = url


    def read_from_distro(self, relpath):

        # read a path relative to the url
        try:
            return urllib.urlopen(os.path.join(self.distroot, relpath)).read()
        except IOError:
            return None

    ## reference-building methods

    def buildref(self):

        if not self.distroot:
            raise 'Distroot not specified'

        print 'Building a reference server at %s using packages in %s' % \
              (self.vpsroot, self.distroot)

        self.ref_make_root() 
        self.ref_install()
        
        # set flags
        self.fixflags()


    def ref_make_root(self):

        print 'Making %s' % self.vpsroot

        os.mkdir(self.vpsroot)
        os.chmod(self.vpsroot, 0755)


    def get_bundle_list(self):

        # find our attributes prefixed with _bundle
        # XXX this method could take an argument to select bundles

        bundles = [n for n in dir(self) if n.startswith('_Bundle_')]
        bundles.sort()

        # put _bundle_base first
        del bundles[bundles.index('_Bundle_base')]
        bundles = ['_Bundle_base'] + bundles

        # instantiate them classes
        return [getattr(self, bundle)(self.distroot, self.vpsroot) for bundle in bundles]


    def ref_install(self):

        # list our package bundles
        bundles = self.get_bundle_list()

        for bundle in bundles:
            bundle.install()
            
        print "DONE"

    def fixflags(self):

        raise "NOT IMPLEMENTED"


class Bundle(object):

    packages = []

    def __init__(self, distroot, vpsroot):
        self.distroot = distroot
        self.vpsroot = vpsroot

    def make_devs(self):
        
        """ This method makes the basic necessary devices.

        On RH systems (and probably others) It has to be called twice
        - once before installing the base system so that rpm can run,
        and then once after the base system has been installed to wipe
        all the numerous devices installed by the dev package and
        revert to the minimal set again.

        XXX This could also be done by way of a custom-crafted dev
        package.

        """

        print 'Making dev in %s' % self.vpsroot

        dev = os.path.join(self.vpsroot, 'dev')

        cmd = 'rm -rf %s' % dev
        commands.getoutput(cmd)

        os.mkdir(dev)
        os.chmod(dev, 0755)

        pts = os.path.join(dev, 'pts')
        os.mkdir(pts)
        os.chmod(pts, 0755)

        for spec in [('null', stat.S_IFCHR, 0666, 1, 3),
                     ('zero', stat.S_IFCHR, 0666, 1, 5),
                     ('full', stat.S_IFCHR, 0666, 1, 7),
                     ('random', stat.S_IFCHR, 0644, 1, 8),
                     ('urandom', stat.S_IFCHR, 0644, 1, 9),
                     ('tty', stat.S_IFCHR, 0666, 5, 0),
                     ('ptmx', stat.S_IFCHR, 0666, 5, 2)]:
            name, mode, perm, maj, min = spec
            os.mknod(os.path.join(dev, name), mode, os.makedev(maj, min))
            os.chmod(os.path.join(dev, name), perm)

        # make an hdv1 "device"
        hdv1 = os.path.join(dev, 'hdv1')
        open(hdv1, 'w')
        os.chmod(hdv1, 0644)
        

