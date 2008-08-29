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

# $Id: RedHat.py,v 1.16 2008/08/29 22:15:52 grisha Exp $

# This is the base class for RedHat (or RedHat-like?) distros.

from Distro import Distro, Bundle
import os
import time
import commands
import urllib
import sys
import shutil
import rpm
import tempfile

from openvps.common import util
from openvps.host import cfg, vsutil

header_info_cache = None

class RedHatBundle(Bundle):

    # when rpm's are pulled from a local disk, they would be stored in
    # distroot/DISTRO_DIR
    DISTRO_DIR = 'RedHat/RPMS'

    # this is an abstract class

    def __init__(self, distroot, vpsroot):

        if not distroot.startswith('http://') and not distroot.startswith('https://'):

            # this is a local file, the rpms are in DISTRO_DIR
            # directory 
            distroot = os.path.join(distroot, self.DISTRO_DIR)


        # call super
        Bundle.__init__(self, distroot, vpsroot)
        

    def install(self):

        # mount dev and proc
        os.chdir(self.vpsroot) # this calms some warnings from following mounts (?)
        cmd = 'mount -t proc none %s' % os.path.join(self.vpsroot, 'proc')
        commands.getoutput(cmd)
        cmd = 'mount -t devpts none %s' % os.path.join(self.vpsroot, 'dev', 'pts')
        commands.getoutput(cmd)

        try:
            print "Installing %s from %s to %s" % (self.desc, self.distroot, self.vpsroot)

            cmd = 'rpm --root %s -Uvh %s' % (self.vpsroot, ' '.join(self.resolve_packages()))
            print cmd
            pipe = os.popen('{ ' + cmd + '; } ', 'r', 0)
            s = pipe.read(1)
            while s:
                sys.stdout.write(s); sys.stdout.flush()
                s = pipe.read(1)
            pipe.close()

        finally:

            # unmount dev and proc
            cmd = 'umount %s' % os.path.join(self.vpsroot, 'proc')
            commands.getoutput(cmd)
            cmd = 'umount %s' % os.path.join(self.vpsroot, 'dev', 'pts')
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
            global header_info_cache

            if header_info_cache:
                hi = header_info_cache
            else:
                hi_url = os.path.join(self.distroot, 'headers/header.info')
                print 'Getting '+hi_url

                hi = urllib.urlopen(hi_url).readlines()

                # cache it
                header_info_cache = hi

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

        os.chdir(os.path.join(self.vpsroot, 'etc', 'init.d'))

        services = os.listdir('.')

        for service in services:
            if service in self.NOT_SERVICES:
                continue
            else:
                onoff = ['off', 'on'][service in self.SERVICES]
                cmd = '%s %s /sbin/chkconfig --level 2345 %s %s' % (cfg.CHROOT, self.vpsroot, service, onoff)
                print '  ', cmd
                pipe = os.popen('{ ' + cmd + '; } ', 'r', 0)
                s = pipe.read(1)
                while s:
                    sys.stdout.write(s); sys.stdout.flush()
                    s = pipe.read(1)
                pipe.close()


    def make_tabs(self):
        """ Make and /etc/fstab and an /etc/mtab """

        fname = os.path.join(self.vpsroot, 'etc', 'fstab')
        print 'Writing %s' % fname
        f = open(fname, 'w')
        f.write(cfg.FSTAB)
        f.close()
        os.chmod(fname, 0644)

        # this is only cosmetic, since the reference server never actually
        # "runs"

        fname = os.path.join(self.vpsroot, 'etc', 'mtab')
        print 'Writing %s' % fname
        f = open(fname, 'w')
        f.write('/dev/hdv1  /       ext2    rw        1       1\n')
        f.close()
        os.chmod(fname, 0644)


    def fix_halt(self):
        """ Replace halt with a simpler version so the
        server stops cleanly"""

        fname = os.path.join(self.vpsroot, 'etc', 'init.d', 'halt')
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

        fname = os.path.join(self.vpsroot, 'etc', 'init.d', 'syslog')
        print 'Removing klogd from %s' % fname

        result = []

        for line in open(fname):
            if 'klogd' in line or 'kernel' in line:
                continue

            result.append(line)

        open(fname, 'w').writelines(result)

    def make_i18n(self):

        print 'Creating etc/sysconfig/i18n.'
        open(os.path.join(self.vpsroot, 'etc/sysconfig/i18n'), 'w').write(
            'LANG="en_US.UTF-8"\n'
            'SUPPORTED="en_US.UTF-8:en_US:en"\n'
            'SYSFONT="latarcyrheb-sun16"\n')

        s = 'localedef -i en_US -c -f UTF-8 en_US.UTF-8'
        print 'Running', s
        cmd = '%s %s %s' % (cfg.CHROOT, self.vpsroot, s)
        commands.getoutput(cmd)


    def fix_inittab(self):

        # we do not want mingetty in the inittab

        file = os.path.join(self.vpsroot, 'etc/inittab')

        print 'Commenting out mingetty lines in', file

        lines  = open(file).readlines()
        for n in range(len(lines)):
            if lines[n].find('mingetty') != -1:
                if not lines[n].strip().startswith('#'):
                    lines[n] ='#' + lines[n]

        open(file, 'w').writelines(lines)

    def make_libexec_openvps(self):

        libexec_dir = os.path.join(self.vpsroot, 'usr/libexec/openvps')

        print 'Making %s' % libexec_dir
        os.mkdir(libexec_dir)

        print 'Copying traceroute there'

        for path, short_name in [('bin/traceroute', 'traceroute'),]:

            # move the originals into libexec/oh
            dest_path = os.path.join(libexec_dir, short_name)
            shutil.move(os.path.join(self.vpsroot, path), dest_path)
            vsutil.set_file_immutable_unlink(dest_path)

            # now place our custom in their path
            dest_path = os.path.join(self.vpsroot, path)

            shutil.copy(os.path.join(cfg.OV_MISC, short_name), dest_path)

            # why can't I do setuid with os.chmod?
            cmd = 'chmod 04755 %s' % dest_path
            commands.getoutput(cmd)

            vsutil.set_file_immutable_unlink(dest_path)

class RedHat(Distro):

    # these are not actually services
    NOT_SERVICES = ['functions', 'killall', 'halt', 'single']

    SERVICES =  ['crond', 'atd', 'httpd', 'sendmail', 'sshd',
                 'syslog', 'webmin', 'dovecot']

    def distro_version(self):

        # is this a redhat distribution?

        discinfo = self.read_from_distro('.discinfo')
        if not discinfo:
            return None

        lines = discinfo.splitlines()[:7]

        if len(lines) < 7:
            # wrong file
            return None

        result = {}
        
        try:
            result['buildtime'] = time.localtime(float(lines[0].strip()))
            result['name'] = lines[1].strip()
            result['platform'] = lines[2]
            # this is a comma-separated list of cd's provided here
            result['volumes'] = lines[3]
            result['base'] = lines[4]
            result['RPMS'] = lines[5]
            result['pixmaps'] = lines[6]
        except "BLAH":
            return None

        return result

    def vps_version(self):

        try:
            return open(os.path.join(self.vpsroot, 'etc/redhat-release')).read()
        except:
            return None


    def vps_arch(self):

        cmd = "/usr/bin/file -b --no-dereference %s/sbin/init" % self.vpsroot
        s = commands.getoutput(cmd)

        if 'x86-64' in s:
            return 'x86_64'
        elif '80386' in s:
            return 'i386' 
        else:
            return None
            

    def fixflags(self):

        # This routine sets immutable-unlink flags on all files,
        # except those that are marked as config (or mentioned at all)
        # in rpms

        print 'Fixing flags in %s ... (this will take a while)' % self.vpsroot

        # progress indicator
        prog_size = 60
        sys.stdout.write('[%s]' % (' '*prog_size)); sys.stdout.flush()
        p = 0

        # list all rpms
        # (rpmlint is a good place to look at Python code when it comes
        #  to completely undocumented rpm-python)

        ts = rpm.TransactionSet(self.vpsroot)
        rpms  = [item[1][rpm.RPMTAG_NAME] for item in ts.IDTXload()]

        # a stupid trick. makes the progress indicator move slow at first
        # then faster (probably because small rpms are towards the end).
        rpms.reverse()

        # this will prevent some warnings related to chroot
        os.chdir(cfg.VSERVERS_ROOT)

        for name in rpms:

            # list files in the rpm
            it = ts.dbMatch('name', name)

            hdr = it.next()

            # this creates a list of file in an rpm. the implementation
            # is borrowed from rpmlint package, i don't really understand
            # how it works, but it does.

            files = hdr[rpm.RPMTAG_OLDFILENAMES]
            if files == None:
                basenames = hdr[rpm.RPMTAG_BASENAMES]
                if basenames:
                    dirnames = hdr[rpm.RPMTAG_DIRNAMES]
                    dirindexes = hdr[rpm.RPMTAG_DIRINDEXES]
                    files=[]
                    if type(dirindexes) == types.IntType:
                        files.append(dirnames[dirindexes] + basenames[0])
                    else:
                        for idx in range(0, len(dirindexes)):
                            files.append(dirnames[dirindexes[idx]] + basenames[idx])

            # now step through those files

            for idx in xrange(len(files)):

                # do we need a pacing sleep?
                if p >= 1000:
                    # instead of writing a dot, write something meaningful
                    prog = int(rpms.index(name)/float(len(rpms))*prog_size)
                    sys.stdout.write('\b'*(prog_size+2))
                    sys.stdout.write('[%s%s]' % ('='*prog, ' '*(prog_size-prog)))
                    sys.stdout.flush()
                    p = 0
                else:
                    p += 1

                flags = hdr[rpm.RPMTAG_FILEFLAGS][idx]

                if not flags & rpm.RPMFILE_CONFIG:
                    # (if not a config file)

                    file = files[idx]

                    # check against our cloning rules
                    c, t, s = self.match_path(file)

                    if c or t or s:
                        # skip it
                        continue
                    else:
                        abspath = os.path.join(self.vpsroot, file[1:])

                        if (os.path.exists(abspath) 
                            and (not os.path.islink(abspath)) 
                            and (not os.path.isdir(abspath))):
                            # (do not make symlinks and dirs immutable)

                            vsutil.set_file_immutable_unlink(abspath)
                            vsutil.set_file_xid(abspath, 0)

                            # NOTE that under no circumstances we *unset* the flag. This
                            # is because e.g. usr/libexec/oh stuff must be iunlink, but
                            # is not in an rpm.
                            # reldst is the way it would look relative to self.vpsroot

        sys.stdout.write('\b'*(prog_size+2))
        sys.stdout.write('[%s]' % ('='*prog_size)); sys.stdout.flush()
        print 'Done.'

    def clone(self, dest, pace=cfg.PACE[0]):

        # pace counter
        p = 0

        # this will also strip trailing slashes
        source, dest = self.vpsroot, os.path.abspath(dest)

        print 'Cloning %s -> %s ... (this will take a while)' % (source, dest)

        # this will prevent some warnings
        os.chdir(cfg.VSERVERS_ROOT)

        self.copy(source, dest)

        for root, dirs, files in os.walk(source):

            for file in files + dirs:

                if pace and p >= pace:
                    sys.stdout.write('.'); sys.stdout.flush()
                    time.sleep(cfg.PACE[1])
                    p = 0
                else:
                    p += 1

                src = os.path.join(root, file)

                # reldst is they way it would look inside vserver
                reldst = os.path.join(max(root[len(source):], '/'), file)
                dst = os.path.join(dest, reldst[1:])

                c, t, s = self.match_path(reldst)

                if not s:
                    link = not c and not self.is_config(source, reldst)
                    self.copy(src, dst, link=link, touch=t)

        print 'Done.'

        print 'Bytes copied:'.ljust(20), self.counter['bytes']
        print 'Links created:'.ljust(20), self.counter['lins']
        print 'Dirs copied:'.ljust(20), self.counter['drs']
        print 'Symlinks copied:'.ljust(20), self.counter['syms']
        print 'Touched files:'.ljust(20), self.counter['touchs']
        print 'Copied files:'.ljust(20), self.counter['copys']
        print 'Devices:'.ljust(20), self.counter['devs']


    rpm_cache = {}

    def is_config(self, root, file):

        ts = rpm.TransactionSet(root)

        if not self.rpm_cache.has_key(file):

            hdr = self.rpm_which_package(ts, root, file)
            if not hdr:
                # assume it's config if not found, this will
                # make sure it is copied, not linked
                self.rpm_cache[file] = {'isconfig':1}
            else:
                self.rpm_cache.update(self.rpm_list_files(hdr))

                # it's possible that which_package thinks a package is of an rpm
                # but then it's not actually there
                if file not in self.rpm_cache:
                    self.rpm_cache[file] = {'isconfig':1}

        ts = None

        return self.rpm_cache[file]['isconfig']

    def rpm_which_package(self, ts, root, file):

        # just like rpm -qf file

        it = ts.dbMatch('basenames', file)

        try:
            hdr = it.next()
        except StopIteration:
            return None

        #return hdr[rpm.RPMTAG_NAME]
        return hdr

    def rpm_list_files(self, hdr):

        # list files in an RPM.

        files=hdr[rpm.RPMTAG_OLDFILENAMES]

        if files == None:

            basenames = hdr[rpm.RPMTAG_BASENAMES]

            if basenames:

                dirnames = hdr[rpm.RPMTAG_DIRNAMES]
                dirindexes = hdr[rpm.RPMTAG_DIRINDEXES]

                files=[]

                if type(dirindexes) == types.IntType:
                    files.append(dirnames[dirindexes] + basenames[0])
                else:
                    for idx in range(0, len(dirindexes)):

                        files.append(dirnames[dirindexes[idx]] + basenames[idx])

        # now stick in a dict
        result = {}
        for idx in xrange(len(files)):
            flags = hdr[rpm.RPMTAG_FILEFLAGS][idx]
            result[files[idx]] = {'isconfig': flags & rpm.RPMFILE_CONFIG}

        return result

    def add_user(self, userid, passwd):
        """ Add a user. This method will guess whether
        the password is already md5 hashed or not (in which
        case it will hash it) """

        print 'Adding user %s' % userid

        comment = 'User %s' % userid

        if passwd[0:3] == '$1$' and len(passwd) > 30:
            # this is a password hash (most likely)
            pass
        else:
            passwd = util.hash_passwd(passwd, md5=1)

        cmd = "%s %s /usr/sbin/adduser -c '%s' -G wheel -p '%s' %s" % \
              (cfg.CHROOT, self.vpsroot, comment, passwd, userid)
        s = commands.getoutput(cmd)

    def set_user_passwd(self, userid, passwd):
        """ Sets password for uerid. This method will guess whether
        the password is already md5 hashed or not (in which case it
        will hash it) """

        print 'Setting password for %s' % userid

        if passwd[0:3] == '$1$' and len(passwd) > 30:
            # this is a password hash (most likely)
            pass
        else:
            passwd = util.hash_passwd(passwd, md5=1)

        cmd = "%s %s /usr/sbin/usermod -p '%s' %s" % \
              (cfg.CHROOT, self.vpsroot, passwd, userid)
        s = commands.getoutput(cmd)

    def make_hosts(self, hostname, ip):

        # call super
        fqdn = Distro.make_hosts(self, hostname, ip)

        # /etc/sysconfig/network. at least xinetd service looks at it
        fname = os.path.join(self.vpsroot, 'etc', 'sysconfig', 'network')
        open(fname, 'w').write('NETWORKING=yes\nHOSTNAME=%s\n' % fqdn)

    def fixup_rc(self):

        # /etc/rc.d/rc needs to end with true

        rc = os.path.join(self.vpsroot, 'etc/rc.d/rc')
        lines = open(rc).readlines()
        if not lines[-1] == 'true\n':
            print 'Appending true to %s' % rc
            lines.append('\ntrue\n')
            open(rc, 'w').writelines(lines)
        else:
            print 'Not appending true to %s as it is already there' % rc

    def stub_www_index_page(self):
        """ Create a stub default www page """

        fname = os.path.join(self.vpsroot, 'var', 'www', 'html', 'index.html')
        print 'Writing %s' % fname

        f = open(fname, 'w')
        f.write(cfg.INDEX_HTML)
        f.close()

    def fix_services(self):
        """ Disable certain services not necessary in vservers """

        print 'Turning off some services...'

        os.chdir(os.path.join(self.vpsroot, 'etc', 'init.d'))

        services = os.listdir('.')

        for service in services:
            if service in self.NOT_SERVICES:
                continue
            else:
                onoff = ['off', 'on'][service in self.SERVICES]
                cmd = '%s %s /sbin/chkconfig --level 2345 %s %s' % (cfg.CHROOT, self.vpsroot, service, onoff)
                print '  ', cmd
                pipe = os.popen('{ ' + cmd + '; } ', 'r', 0)
                s = pipe.read(1)
                while s:
                    sys.stdout.write(s); sys.stdout.flush()
                    s = pipe.read(1)
                pipe.close()

    def make_ssl_cert(self, hostname):

        if os.path.exists(os.path.join(self.vpsroot, 'etc/httpd/conf/ssl.crt/.ohcert')):
            print 'NOT generating an SSL certificate, it appears to be there already.'
            return

        print 'Generating an SSL certificate...'

        # now make a cert
        ssl_conf = cfg.SSL_CONFIG.replace('@SSL_HOSTNAME@', hostname)
        d = tempfile.mkdtemp()
        f = open(os.path.join(d, "ssl.cfg"), 'w')
        f.write(ssl_conf)
        f.close()
        s = commands.getoutput('openssl req -new -x509 -days 3650 -nodes -config %s '
                           '-out %s/server.crt -keyout %s/server.key' % (os.path.join(d, 'ssl.cfg'), d, d))
        print s
        s = commands.getoutput('openssl x509 -subject -dates -fingerprint -noout -in %s/server.crt' %d)
        print s
        shutil.copy(os.path.join(d, 'server.crt'),  os.path.join(self.vpsroot, 'etc/httpd/conf/ssl.crt/server.crt'))
        shutil.copy(os.path.join(d, 'server.key'),  os.path.join(self.vpsroot, 'etc/httpd/conf/ssl.key/server.key'))
        os.chmod(os.path.join(self.vpsroot, 'etc/httpd/conf/ssl.crt/server.crt'), 0700)
        os.chmod(os.path.join(self.vpsroot, 'etc/httpd/conf/ssl.key/server.key'), 0700)
        commands.getoutput('cat %s %s > %s' % (os.path.join(d, 'server.crt'), os.path.join(d, 'server.key'),
                                               os.path.join(self.vpsroot, 'usr/share/ssl/certs/imapd.pem')))
        commands.getoutput('cat %s %s > %s' % (os.path.join(d, 'server.crt'), os.path.join(d, 'server.key'),
                                               os.path.join(self.vpsroot, 'usr/share/ssl/certs/ipop3d.pem')))
        commands.getoutput('cat %s %s > %s' % (os.path.join(d, 'server.crt'), os.path.join(d, 'server.key'),
                                               os.path.join(self.vpsroot, 'etc/webmin/miniserv.pem')))
        commands.getoutput('cat %s %s > %s' % (os.path.join(d, 'server.crt'), os.path.join(d, 'server.key'),
                                               os.path.join(self.vpsroot, 'usr/share/ssl/certs/dovecot.pem')))
        commands.getoutput('cat %s %s > %s' % (os.path.join(d, 'server.crt'), os.path.join(d, 'server.key'),
                                               os.path.join(self.vpsroot, 'usr/share/ssl/private/dovecot.pem')))
        s = commands.getoutput('rm -rf %s' % d)
        print s
        open(os.path.join(self.vpsroot, 'etc/httpd/conf/ssl.crt/.ohcert'), 'w').write('')

    def fixup_crontab(self):

        print 'Adding rndsleep and randomized crontab'

        fname = os.path.join(self.vpsroot, 'usr/local/bin/rndsleep')
        open(fname, 'w').write(cfg.RNDSLEEP)
        os.chmod(fname, 0755)

        open(os.path.join(self.vpsroot, 'etc/crontab'), 'w').write(cfg.CRONTAB)

    def webmin_passwd(self):

        # copy root password to webmin

        if not os.path.exists(os.path.join(self.vpsroot, 'etc/webmin')):
            print 'webmin not installed, skipping'
            return
        else:
            print 'Setting webmin password'

        shadow = os.path.join(self.vpsroot, 'etc/shadow')
        root_hash = ''
        for line in open(shadow):
            if line.startswith('root:'):
                root_hash = line.split(':')[1]
                break

        musers = os.path.join(self.vpsroot, 'etc/webmin/miniserv.users')
        open(musers, 'w').write('root:%s:0' % root_hash)
        os.chmod(musers, 0600)

    def fixup_libexec_openvps(self):

        # This sets the right permissions for the files in
        # usr/libexec/oh

        print 'Setting flags in usr/libexec/openvps'

        for file in ['traceroute',]:

            path = os.path.join(self.vpsroot, 'usr/libexec/openvps/', file)
            vsutil.set_file_immutable_unlink(path)

    def customize(self, name, xid, ip, userid, passwd, disklim, dns=cfg.PRIMARY_IP,
                  vpn_ip=None, vpn_mask='255.255.255.0'):

        # call super
        Distro.customize(self, name, xid, ip, userid, passwd, disklim, dns,
                         vpn_ip, vpn_mask)

        self.fixup_rc()
        self.webmin_passwd()
        self.fixup_libexec_openvps()
        
    def custcopy(self, source, name, userid, data={}, dns=cfg.PRIMARY_IP):

        xid = Distro.custcopy(self, source, name, userid, data, dns)

        self.fixup_rc()
        self.webmin_passwd()
        self.fixup_libexec_openvps()

        return xid
