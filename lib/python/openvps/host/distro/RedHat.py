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

# $Id: RedHat.py,v 1.3 2005/06/10 03:09:21 grisha Exp $

# This is the base class for RedHat (or RedHat-like?) distros.

from Distro import Distro, Bundle, VPS
import os
import time

from openvps.host import cfg

class RedHatBundle(Bundle):

    # this is an abstract class

    def install(self):

        # mount dev and proc
        os.chdir(self.refroot) # this calms some warnings from following mounts (?)
        cmd = 'mount -t proc none %s' % os.path.join(self.refroot, 'proc')
        commands.getoutput(cmd)
        cmd = 'mount -t devpts none %s' % os.path.join(self.refroot, 'dev', 'pts')
        commands.getoutput(cmd)

        try:
            print "Installing %s from %s to %s" (self.desc, self.distroot, self.refroot)

            cmd = 'rpm --root %s -Uvh %s' % (self.refroot, ' '.join(self.resolve_packages()))
            pipe = os.popen('{ ' + cmd + '; } ', 'r', 0)
            s = pipe.read(1)
            while s:
                sys.stdout.write(s); sys.stdout.flush()
                s = pipe.read(1)
                pipe.close()

        finally:

            # unmount dev and proc
            cmd = 'umount %s' % os.path.join(self.refroot, 'proc')
            commands.getoutput(cmd)
            cmd = 'umount %s' % os.path.join(self.refroot, 'dev', 'pts')
            commands.getoutput(cmd)

        print "DONE"

    def resolve_packages(self):

        # XXX for whatever reason we were having a difficult time with
        # passing urls to rpm -i (as if its http implementation is
        # buggy - in some setups with proxy it just wouldn't work)

        # This walks through the list, looking for entries beginning
        # with 'http:', downloads them to a temporary location
        # (cfg.RPM_CACHE). For other packages it finds the matching
        # version of an rpm in self.distroot

        if not os.path.exists(cfg.RPM_CACHE):
            print 'Creating directory', cfg.RPM_CACHE
            os.mkdir(cfg.RPM_CACHE)

        ## read current dir or headers.info into a dict keyed by the
        ## beginning of a file

        pkgdict = {}

        if self.distroot.startswith('http://') or self.distroot.startswith('https://'):

            ### the distroot is a url

            # we rely on header.info file
            hi_url = os.path.join(self.distroot, 'headers/header.info')
            print 'Getting '+hi_url

            hi = urllib.urlopen(hi_url).readlines()

            for line in hi:
                rpm_name, rpm_path = line.strip().split(':')[1].split('=')
                name = '-'.join(rpm_name.split('-')[:-2])
                pkgdict[name] = os.path.join(self.distroot, rpm_path)

        else:

            ### the distroot is a local directory

            files = os.listdir(self.distroot)
            files.sort()
            pkgdict = {}
            for f in files:
                # everything but the last two dash separated parts
                name = '-'.join(f.split('-')[:-2])
                pkgdict[name] = f

        ## go throught the list and pull the files as needed

        result = []

        for pkg in self.packages:

            if self.distroot.startswith('http://') or self.distroot.startswith('https://'):
                # if distroot is a url, 
                if not (pkg.startswith('http://') or pkg.startswith('https://')):
                    # and this package is not a url, then replace a package name with its url
                    pkg = pkgdict[pkg]

            if pkg.startswith('http://') or pkg.startswith('https://'):

                # remote package

                basename = os.path.split(pkg)[1]

                cache_file = os.path.join(cfg.RPM_CACHE, basename)
                if not os.path.exists(cache_file):
                    print 'Retrieveing %s -> %s' % (pkg, cache_file)
                    f = urllib.urlopen(pkg)
                    s = f.read()
                    open(os.path.join(cfg.RPM_CACHE, basename), 'wb').write(s)
                else:
                    print 'Cached copy of %s exists as %s, not retrieving' % (basename, cache_file)

                result.append(cache_file)

            else:
                # non-specific package, resolve it
                result.append(os.path.join(self.distroot, pkgdict[pkg]))

        return result


class RedHat_Bundle_base(RedHatBundle):

    desc  = 'RedHat Base Abstract Bundle'

    # these are not actually services
    NOT_SERVICES = ['functions', 'killall', 'halt', 'single']

    SERVICES =  ['crond', 'atd', 'httpd', 'sendmail', 'sshd',
                 'syslog', 'webmin', 'dovecot']

    def install(self):

        # call our super
        self.make_devs()
        RedHatBundle.install(self)
        self.make_devs() # yes, again

        self.make_tabs()
        self.fix_services()
        self.fix_halt()
        self.fix_syslog()
        self.make_i18n()
        self.fix_inittab()
        self.make_libexec_openvps()

    def fix_services(self):
        """ Disable certain services not necessary in vservers """

        print 'Turning off some services...'

        os.chdir(os.path.join(self.refroot, 'etc', 'init.d'))

        services = os.listdir('.')

        for service in services:
            if service in NOT_SRVCS:
                continue
            else:
                onoff = ['off', 'on'][service in SERVICES]
                cmd = '%s %s /sbin/chkconfig --level 2345 %s %s' % (cfg.CHROOT, self.refroot, service, onoff)
                print '  ', cmd
                pipe = os.popen('{ ' + cmd + '; } ', 'r', 0)
                s = pipe.read(1)
                while s:
                    sys.stdout.write(s); sys.stdout.flush()
                    s = pipe.read(1)
                pipe.close()


    def make_tabs(self):
        """ Make and /etc/fstab and an /etc/mtab """

        fname = os.path.join(self.refroot, 'etc', 'fstab')
        print 'Writing %s' % fname
        f = open(fname, 'w')
        f.write(cfg.FSTAB)
        f.close()
        os.chmod(fname, 0644)

        # this is only cosmetic, since the reference server never actually
        # "runs"

        fname = os.path.join(self.refroot, 'etc', 'mtab')
        print 'Writing %s' % fname
        f = open(fname, 'w')
        f.write('/dev/hdv1  /       ext2    rw        1       1\n')
        f.close()
        os.chmod(fname, 0644)


    def fix_halt(refroot):
        """ Replace halt with a simpler version so the
        server stops cleanly"""

        fname = os.path.join(self.refroot, 'etc', 'init.d', 'halt')
        print 'Writing %s' % fname

        f = open(fname, 'w')
        f.write('#!/bin/bash\n'
                '#\n'
                '# halt          This file is executed by init when it goes into runlevel\n'
                '#               0 (halt) or runlevel 6 (reboot). It kills all processes,\n'
                '#               unmounts file systems and then either halts or reboots.\n'
                '#\n'
                '# This is an OpenHosting version of this file\n'
                'NOLOCALE=1\n'
                '. /etc/init.d/functions\n'
                'echo "Sending all processes the TERM signal..."\n'
                '/sbin/killall5 -15\n'
                'sleep 5\n'
                'echo "Sending all processes the KILL signal..."\n'
                '/sbin/killall5 -9\n\n'
                r"mount |  awk '!/( \/ |^\/dev\/root|^\/dev\/ram| \/proc )/ { print $3 }' | \ "
                '\nwhile read line; do\n'
                '    umount -f $line\n'
                'done\n'
                '\n/sbin/reboot -n\n')
        f.close()

        def fix_syslog(self):
            """ Remove references to klogd in syslog service """

            fname = os.path.join(self.refroot, 'etc', 'init.d', 'syslog')
            print 'Removing klogd from %s' % fname

            result = []

            for line in open(fname):
                if 'klogd' in line or 'kernel' in line:
                    continue

                result.append(line)

            open(fname, 'w').writelines(result)

        def make_i18n(self):

            print 'Creating etc/sysconfig/i18n.'
            open(os.path.join(refroot, 'etc/sysconfig/i18n'), 'w').write(
                'LANG="en_US.UTF-8"\n'
                'SUPPORTED="en_US.UTF-8:en_US:en"\n'
                'SYSFONT="latarcyrheb-sun16"\n')

            s = 'localedef -i en_US -c -f UTF-8 en_US.UTF-8'
            print 'Running', s
            cmd = '%s %s %s' % (cfg.CHROOT, self.refroot, s)
            commands.getoutput(cmd)


        def fix_inittab(self):

            # we do not want mingetty in the inittab

            file = os.path.join(self.refroot, 'etc/inittab')

            print 'Commenting out mingetty lines in', file

            lines  = open(file).readlines()
            for n in range(len(lines)):
                if lines[n].find('mingetty') != -1:
                    if not lines[n].strip().startswith('#'):
                        lines[n] ='#' + lines[n]

            open(file, 'w').writelines(lines)

        def make_libexec_openvps(self):

            libexec_dir = os.path.join(self.refroot, 'usr/libexec/openvps')

            print 'Making %s' % libexec_dir
            os.mkdir(libexec_dir)

            print 'Copying traceroute there'

            for path, short_name in [('bin/traceroute', 'traceroute'),]:

                # move the originals into libexec/oh
                dest_path = os.path.join(libexec_dir, short_name)
                shutil.move(os.path.join(refroot, path), dest_path)
                vsutil.set_file_immutable_unlink(dest_path)

                # now place our custom in their path
                dest_path = os.path.join(refroot, path)

                shutil.copy(os.path.join(cfg.OV_MISC, short_name), dest_path)

                # why can't I do setuid with os.chmod?
                cmd = 'chmod 04755 %s' % dest_path
                commands.getoutput(cmd)

                vsutil.set_file_immutable_unlink(dest_path)

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

class RedHat_VPS(VPS):

    def __init__(self, vpsroot):

        self.vpsroot = vpsroot

    def distro_version(self):

        try:
            return open(os.path.join(self.vpsroot, 'etc/redhat-release')).read()
        except:
            return None


