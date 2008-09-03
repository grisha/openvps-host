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

# $Id: Distro.py,v 1.20 2008/09/03 22:09:02 grisha Exp $

# this is the base object for all distributions, it should only contain
# methods specific to _any_ distribution

import urllib
import os
import commands
import stat
import shutil
import sys
import time
import re

from openvps.common import util
from openvps.host import cfg, vsutil

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

    def buildref(self, bundles=None):

        if not self.distroot:
            raise 'Distroot not specified'

        print 'Building a reference server at %s using packages in %s' % \
              (self.vpsroot, self.distroot)

        self.ref_make_root() 
        self.ref_install(bundles)
        
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


    def ref_install(self, bundles):

        # list our package bundles
        available_bundles = self.get_bundle_list()

        for bundle in available_bundles:
            if bundles and bundle.name not in bundles:
                continue # skip it
            bundle.install()
            
        print "DONE"

    def fixflags(self):

        raise "NOT IMPLEMENTED"

    def clone(self, dest):

        raise "NOT IMPLEMENTED"

    def match_path(self, path):
        """Return copy, touch pair based on config rules for this path"""

        # this could be made distro specific

        # if the patch begins with a /, then assume that we want to
        # match only at the beginning, otherwise it's just a regular
        # exp

        copy_exp, touch_exp, skip_exp = cfg.CLONE_RULES

        return copy_exp and not not copy_exp.search(path), \
               touch_exp and not not touch_exp.search(path), \
               skip_exp and not not skip_exp.search(path)


    def copyown(self, src, dst):
        """Copy ownership"""
        
        st = os.lstat(src)
        os.lchown(dst, st.st_uid, st.st_gid)


    counter = {'bytes':0, 'lins':0, 'drs':0, 'syms':0, 'touchs':0,
               'copys':0, 'devs':0}

    def copy(self, src, dst, link=1, touch=0):
        """Copy a file, a directory or a link.  When link is 1
        (default), regular files will be hardlinked, as opposed to
        being copied. When touch is 1, only the file, but not the
        contents are copied (useful for logfiles).  """

        if os.path.islink(src):

            # if it is a symlink, always copy it (no sense in trying
            # to hardlink a symlink)

            os.symlink(os.readlink(src), dst)
            self.copyown(src, dst)
            self.counter['syms'] += 1

        elif os.path.isdir(src):

            # directories are also copied always

            os.mkdir(dst)
            self.copyown(src, dst)
            shutil.copystat(src, dst)
            self.counter['drs'] += 1

        elif os.path.isfile(src):

            # this a file, not a dir or symlink

            if touch:

                # means create a new file and copy perms

                open(dst, 'w')
                self.copyown(src, dst)
                shutil.copystat(src, dst)
                self.counter['touchs'] += 1

            elif link:

                # means we should hardlink

                if vsutil.is_file_immutable_unlink(src):
                    os.link(src, dst)
                    self.counter['lins'] += 1
                else:
                    # since it is not iunlink, copy it anyway
                    print 'Warning: not hardlinking %s because it is not iunlink' % src
                    shutil.copy(src, dst)
                    self.copyown(src, dst)
                    shutil.copystat(src, dst)
                    self.counter['bytes'] += os.path.getsize(dst)
                    self.counter['copys'] += 1

            else:

                # else copy it

                shutil.copy(src, dst)
                self.copyown(src, dst)
                shutil.copystat(src, dst)
                self.counter['bytes'] += os.path.getsize(dst)
                self.counter['copys'] += 1

        else:

            # this is a special device?

            s = os.stat(src)
            if stat.S_ISBLK(s.st_mode) or stat.S_ISCHR(s.st_mode) \
               or stat.S_ISFIFO(s.st_mode):
                os.mknod(dst, s.st_mode, os.makedev(os.major(s.st_rdev),
                                                    os.minor(s.st_rdev)))
                self.copyown(src, dst)
                shutil.copystat(src, dst)
                self.counter['devs'] += 1

    def add_user(self, userid, passwd):
        raise "NOT IMPLEMENTED"

    def set_user_passwd(self, userid, passwd):
        raise "NOT IMPLEMENTED"

    def make_hosts(self, hostname, ip):

        fname = os.path.join(self.vpsroot, 'etc', 'hosts')
        print 'Writing %s' % fname

        fqdn = hostname
        host = hostname.split('.')[0]

        kern_ver =  commands.getoutput("uname -r")
        if re.search(r'vs[12]\.[012]', kern_ver):
            # old vserver, localhost must point the IP of the VPS
            open(fname, 'w').write('%s %s %s localhost' % (ip, fqdn, host))
        else:
            # assume new vserver (2.3+), normal hosts file
            open(fname, 'w').write('127.0.0.1 localhost\n%s %s %s\n' % (ip, fqdn, host))

        return fqdn

    def enable_sudo(self):
        """ Enable sudoing for anyone in the wheel group """

        print 'Enabling sudo access for wheel group'

        sudoers = os.path.join(self.vpsroot, 'etc/sudoers')

        lines = open(sudoers).readlines()

        for n in range(len(lines)):
            if lines[n].startswith('# %wheel') and 'NOPASSWD' not in lines[n]:
                lines[n] = lines[n][2:]
                break

        open(sudoers, 'w').writelines(lines)
        
    def make_resolv_conf(self, dns1, dns2=None, search=None):

        fname = os.path.join(self.vpsroot, 'etc', 'resolv.conf')
        print 'Writing %s' % fname

        f = open(fname, 'w')
        f.write('nameserver %s\n' % dns1)
        if dns2:
            f.write('nameserver %s\n' % dns2)
        if search:
            f.write('search %s\n' % search)

    def config_sendmail(self, hostname):

        fname = os.path.join(self.vpsroot, 'etc', 'mail', 'local-host-names')
        print 'Writing %s' % fname

        fqdn = hostname
        domain = hostname.split('.', 1)[-1]

        f = open(fname, 'w')
        f.write('\n%s\n' % fqdn)
        if '.' in domain:
            f.write('%s\n' % domain)
        f.close()

    def stub_www_index_page(self):
        raise "NOT_IMPLEMENTED"

    def make_motd(self):

        fname = os.path.join(self.vpsroot, 'etc', 'motd')
        print 'Writing %s' % fname

        # customize motd
        f = open(fname, 'w')
        f.write(cfg.MOTD)
        f.close()

    def make_openvpn_conf(self, tap_name, vpn_ip, vpn_mask):

        print 'Creating openvpn/openvps.conf...'

        openvpn_dir = os.path.join(self.vpsroot, 'etc', 'openvpn')

        if not os.path.exists(openvpn_dir):
            os.mkdir(openvpn_dir)
            os.chmod(openvpn_dir, 0500)

        fname = os.path.join(openvpn_dir, 'openvps.conf')
        print 'Writing %s' % fname

        s =  "\n## The following is VPS-specific, DO NOT CHANGE\n"
        s += "dev %s\n" % tap_name
        s += "ifconfig %s %s\n" % (vpn_ip, vpn_mask)
        s += "ifconfig-noexec\n"
        s += "## END VPS-specific stuff\n\n"
        s += "# use TCP\n"
        s += "proto tcp-server\n\n"
        s += "# Use a static key\n"
        s += "secret static.key\n\n"
        s += "# Allow client IP change\n"
        s += "float\n\n"
        s += "# Drop privileges\n"
        s += "user nobody\n"
        s += "persist-key\n"
        s += "persist-tun\n\n"
        s += "keepalive 10 60\n\n"
        s += "# Be verbose\n"
        s += "#verb 4\n\n"
        
        open(fname, 'w').write(s)

        # generate key
        fname = os.path.join(openvpn_dir, 'static.key')
        print "Generating OpenVPN static key...."
        
        cmd = "openvpn --genkey --secret %s" % fname
        print commands.getoutput(cmd)

        os.chmod(fname, 0600)
        
        return
    
    def fix_services(self):
        raise "NOT IMPLEMENTED"

    def disk_limit(self, xid, limit, d_used=0, i_used=0, force=False):

        if not force:
            dldb = os.path.join(cfg.VAR_DB_OPENVPS, 'disklimits', 'disklimits')
            for line in open(dldb):
                if '--xid %s ' % xid in line:
                    print 'NOT setting disk limits, they exist already for xid %s' % xid
                    return

        print 'Setting disk limits...'

        vsutil.set_disk_limits(xid, d_used, limit, i_used, cfg.INODES_LIM, 5, cfg.VSERVERS_ROOT)

    def make_ssl_cert(self):
        raise "NOT IMPLEMENTED"

    def fixup_crontab(self):
        raise "NOT IMPLEMENTED"

    def ohd_key(self, name):

        # create an ohd key, and add it to
        # allowed keys of the ohd user on the host

        keyfile = os.path.join(self.vpsroot, 'etc/ohd_key')

        if os.path.exists(keyfile):
            print 'NOT touching already existing key', keyfile
            return

        print 'Generating ssh key', keyfile

        cmd = 'ssh-keygen -t rsa -b 768 -N "" -f %s' % keyfile
        commands.getoutput(cmd)

        ohdkeys = '/home/ohd/.ssh/authorized_keys'
        print 'Adding it to', ohdkeys

        key = open(keyfile+'.pub').read()
        s = 'from="127.0.0.1,::ffff:127.0.0.1",command="/usr/bin/sudo %s %s" %s' % \
            (os.path.join(cfg.MISC_DIR, 'ohdexec'), name, key)

        open(ohdkeys, 'a+').write(s)

    def immutable_modules(self):

        # make lib/modules immutable. we already have a fake kernel
        # installed, but this will serve as a further deterrent against
        # installing kernels and/or modules. This flag can be unset from
        # within a vserver.

        print 'Making lib/modules immutable'

        cmd = 'chattr +i %s' % os.path.join(self.vpsroot, 'lib/modules')
        s = commands.getoutput(cmd)
        if s: print s

    def make_snapshot_dir(self):

        # This is used when you have a snaphosts backup server

        snapshot = os.path.join(self.vpsroot, 'snapshot')

        if not (os.path.isdir(snapshot)):

            print 'Creating %s directory' % snapshot

            os.mkdir(snapshot)
            os.chmod(snapshot, 0500)

        else:

            print '%s already exists, not creating' % snapshot

    def fixxids(self, xid, pace=cfg.PACE[0]):

        # walk the root, and set all non-iunlink files to xid xid.  this
        # means that when a non iunlink file is deleted, the proper amount
        # of space is freed.

        xid = int(xid)

        print 'Fixing xids in %s for xid %d... (this may take a while)' % (self.vpsroot, xid)

        p = 0
        t, x = 0, 0

        for root, dirs, files in os.walk(self.vpsroot):

            for file in files + dirs:

                path = os.path.join(root, file)

                if pace and p >= pace:
                    sys.stdout.write('.'); sys.stdout.flush()
                    time.sleep(cfg.PACE[1])
                    p = 0
                else:
                    p += 1

                t += 1  # total file count

                if os.path.isdir(path) or path.endswith('dev/null') or \
                       path.endswith('etc/protocols') or path.endswith('etc/resolv.conf'):

                    # do not set xid on directories, as this breaks the ohd
                    # thing which would get permission denied trying to run
                    # stuff from another context. since space (not security) is
                    # the prime motivator for this, and dirs are tiny, this is ok
                    # XXX and of course the dev/null and etc/protocols is a total
                    # dirty hack to make traceroute work

                    # XXX or is it?

                    vsutil.set_file_xid(path, 0)

                elif (not vsutil.is_file_immutable_unlink(path) and
                      not os.path.islink(path) and
                      os.stat(path).st_nlink == 1):

                    vsutil.set_file_xid(path, xid)

                    x += 1 # setxid file count

                elif not os.path.islink(path):

                    # default to 0
                    vsutil.set_file_xid(path, 0)
                    

        print 'Done.\n%d xids of a total of %d has been set to %d' % (x, t, xid)

    def customize(self, name, xid, ip, userid, passwd, disklim, dns=cfg.PRIMARY_IP,
                  vpn_ip=None, vpn_mask='255.255.255.0'):

        hostname = name + '.' + cfg.DEFAULT_DOMAIN

        vps_arch = self.vps_arch()

        # first make a configuration
        vsutil.save_vserver_config(name, ip, xid, hostname,
                                   vpn_ip=vpn_ip, vpn_mask=vpn_mask,
                                   vps_arch=vps_arch)

        root = self.vpsroot

        # no do this boring crap.....

        self.set_user_passwd('root', passwd)
        self.add_user(userid, passwd)
        self.enable_sudo()
        self.make_hosts(hostname, ip)

        search = '.'.join(hostname.split('.')[1:])
        if '.' not in search:
            search = hostname
        self.make_resolv_conf(dns, search=search)

        self.config_sendmail(hostname)
        self.stub_www_index_page()
        self.make_motd()
        self.fix_services()
        self.disk_limit(xid, disklim)
        self.make_ssl_cert(hostname)
        self.fixup_crontab()
        self.ohd_key(name)
        self.immutable_modules()
        self.make_snapshot_dir()
        if vpn_ip:
            self.make_openvpn_conf('tap_'+name, vpn_ip, vpn_mask)

    def get_user_passwd(self, userid):

        # read the password hash from /etc/shadow. if it is not there,
        # None will be returned.
        
        passwd = None

        shadow = os.path.join(self.vpsroot, 'etc/shadow')
        if os.path.exists(shadow):
            lines = open(shadow).readlines()
            for line in lines:
                parts = line.split(':')
                if len(parts) > 2 and parts[0] == userid:
                    passwd = parts[1]
                    break

        return passwd

    def cancopy(self):

        # this method will examine ourselves to see if we have
        # everything in place to get copied. it will return a list of
        # missing elements that would need to be explicitely
        # specified.

        result = []
        
        if not self.get_user_passwd('root'):
            result.append('root_passwd')

        return result

    def custcopy(self, source, name, userid, data={}, dns=cfg.PRIMARY_IP):

        # this will customize a newly cloned VPS, but by copying files
        # from the source VPS, which should be an instance of a Distro
        # subclass.

        config = vsutil.get_vserver_config(name)

        # root password
        if not data.has_key('root_passwd'):
            data['root_passwd'] = source.get_user_passwd('root')
            if not data['root_passwd']:
                raise "Missing root password"
        self.set_user_passwd('root', data['root_passwd'])

        # user password
        if not data.has_key('user_passwd'):
            data['user_passwd'] = source.get_user_passwd('userid')
            if not data['user_passwd']:
                data['user_passwd'] = data['root_passwd']
        self.add_user(userid, data['user_passwd'])

        self.enable_sudo()
        
        hostname = config['hostname']
        ip = config['interfaces'][0]['ip']
        self.make_hosts(hostname, ip)

        search = '.'.join(hostname.split('.')[1:])
        if '.' not in search:
            search = hostname
        self.make_resolv_conf(dns, search=search)

        self.config_sendmail(hostname)
        self.stub_www_index_page()
        self.make_motd()
        self.fix_services()

        xid = config['context']
        disklim = vsutil.get_disk_limits(xid)
        if not disklim or not disklim.has_key('b_total'):
            disklim = 3000000
        else:
            disklim = disklim['b_total']
        
        self.disk_limit(xid, disklim, force=True)

        self.make_ssl_cert(hostname)
        self.fixup_crontab()

        if os.path.exists(os.path.join(source.vpsroot, 'etc/ohd_key')) and \
               os.path.exists(os.path.join(source.vpsroot, 'etc/ohd_key.pub')):
            for file in ['etc/ohd_key', 'etc/ohd_key.pub']:
                src = os.path.join(source.vpsroot, file)
                dst = os.path.join(self.vpsroot, file)
                shutil.copy(src, dst)
                self.copyown(src, dst)
                shutil.copystat(src, dst)
        else:
            self.ohd_key(name)
        self.immutable_modules()
        self.make_snapshot_dir()

        return xid
                                                                                                
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

        net = os.path.join(dev, 'net')
        os.mkdir(net)
        os.chmod(net, 0755)

        for spec in [('null', stat.S_IFCHR, 0666, 1, 3),
                     ('zero', stat.S_IFCHR, 0666, 1, 5),
                     ('full', stat.S_IFCHR, 0666, 1, 7),
                     ('random', stat.S_IFCHR, 0644, 1, 8),
                     ('urandom', stat.S_IFCHR, 0644, 1, 9),
                     ('tty', stat.S_IFCHR, 0666, 5, 0),
                     ('ptmx', stat.S_IFCHR, 0666, 5, 2),
                     ('net/tun', stat.S_IFCHR, 0600, 10, 200)]:
            name, mode, perm, maj, min = spec
            os.mknod(os.path.join(dev, name), mode, os.makedev(maj, min))
            os.chmod(os.path.join(dev, name), perm)

        # make an hdv1 "device"
        hdv1 = os.path.join(dev, 'hdv1')
        open(hdv1, 'w')
        os.chmod(hdv1, 0644)

        # make the fd symlink
        os.symlink('../proc/self/fd', os.path.join(dev, 'fd'))
        

