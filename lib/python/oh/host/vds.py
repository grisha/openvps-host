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

# $Id: vds.py,v 1.29 2004/10/16 05:05:19 grisha Exp $

""" VDS related functions """

import os
import sys
import stat
import shutil
import re
import commands
import tempfile
import time
import urllib

# oh modules
import cfg
import vsutil
from oh.common import util

DRYRUN = 0


def ref_make_root(root):

    print 'Making %s' % root

    os.mkdir(root)
    os.chmod(root, 0755)

def ref_make_devs(root):
    """ This func makes the basic necessary devices. It has
    to be clled twice - once before installing the base system
    so that rpm can run, and then once after the base system has
    been installed to wipe all the numerous devices installed by
    the dev package and revert to the minimal set again. """

    print 'Making dev in %s' % root

    dev = os.path.join(root, 'dev')

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

    # XXX what does this do?
    hdv1 = os.path.join(dev, 'hdv1')
    open(hdv1, 'w')
    os.chmod(hdv1, 0644)

def resolve_packages(pkglist, distroot='.'):

    # XXX for whatever reason we were having a difficult time with passing urls
    # to rpm -i (as if it's http implementation is buggy - in some setups with proxy
    # it just wouldn't work)

    # This walks through the list, looking for entries beginning with 'http:', downloads
    # them to a temporary location (cfg.RPM_CACHE)

    # for other packages it finds the matching version of an rpm in the current dir

    if not os.path.exists(cfg.RPM_CACHE):
        print 'Creating directory', cfg.RPM_CACHE
        os.mkdir(cfg.RPM_CACHE)

    ## read current dir or headers.info into a dict keyed by the beginning of a file
    
    pkgdict = {}

    if distroot.startswith('http://') or distroot.startswith('https://'):
        
        # the distroot is a url

        # we rely on header.info file
        hi_url = os.path.join(distroot, 'headers/header.info')
        print 'Getting '+hi_url
        
        hi = urllib.urlopen(hi_url).readlines()

        for line in hi:
            rpm_name, rpm_path = line.strip().split(':')[1].split('=')
            name = '-'.join(rpm_name.split('-')[:-2])
            pkgdict[name] = os.path.join(distroot, rpm_path)

    else:

        # the distroot is a local directory
    
        files = os.listdir(distroot)
        files.sort()
        pkgdict = {}
        for f in files:
            # everything but the last two dash separated parts
            name = '-'.join(f.split('-')[:-2])
            pkgdict[name] = f

    ## go throught the list and pull the files as needed

    result = []

    for pkg in pkglist:

        if distroot.startswith('http://') or distroot.startswith('https://'):
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
            result.append(pkgdict[pkg])

    return result
                
def ref_install_pkgs(root, distroot):

    print 'Installing packages from %s' % distroot

    os.mkdir(os.path.join(root, 'var'))
    os.mkdir(os.path.join(root, 'var', 'lib'))
    os.mkdir(os.path.join(root, 'var', 'lib', 'rpm'))

    os.mkdir(os.path.join(root, 'proc'))

    os.chdir(root) # this calms some warnings from following mounts (?)

    cmd = 'mount -t proc none %s' % os.path.join(root, 'proc')
    commands.getoutput(cmd)

    cmd = 'mount -t devpts none %s' % os.path.join(root, 'dev', 'pts')
    commands.getoutput(cmd)

    try:
        #os.chdir(distroot)
        
        print "Installing base packages STEP I..."
        cmd = 'rpm --root %s -Uvh %s' % (root, ' '.join(resolve_packages(cfg.FEDORA_C2_PKGS_BASE_I, distroot)))
        pipe = os.popen('{ ' + cmd + '; } ', 'r', 0)
        s = pipe.read(1)
        while s:
            sys.stdout.write(s); sys.stdout.flush()
            s = pipe.read(1)
        pipe.close()

        # another mising dir
        if not os.path.isdir(os.path.join(root, 'usr')):
            os.mkdir(os.path.join(root, 'usr'))
        if not os.path.isdir(os.path.join(root, 'usr', 'src')):
            os.mkdir(os.path.join(root, 'usr', 'src'))
        os.mkdir(os.path.join(root, 'usr', 'src', 'redhat'))

        print "Installing packages STEP II..."
        cmd = 'rpm --root %s -Uvh %s' % (root, ' '.join(resolve_packages(cfg.FEDORA_C2_PKGS_BASE_II, distroot)))
        pipe = os.popen('{ ' + cmd + '; } ', 'r', 0)
        s = pipe.read(1)
        while s:
            sys.stdout.write(s); sys.stdout.flush()
            s = pipe.read(1)
        pipe.close()


        if cfg.FEDORA_C2_PKGS_ADDL:
        
            print "Installing additional packages..."
            cmd = 'rpm --root %s -Uvh %s' % (root, ' '.join(resolve_packages(cfg.FEDORA_C2_PKGS_ADDL, distroot)))
            pipe = os.popen('{ ' + cmd + '; } ', 'r', 0)
            s = pipe.read(1)
            while s:
                sys.stdout.write(s); sys.stdout.flush()
                s = pipe.read(1)
            pipe.close()

        
    finally:

        cmd = 'umount %s' % os.path.join(root, 'proc')
        commands.getoutput(cmd)

        cmd = 'umount %s' % os.path.join(root, 'dev', 'pts')
        commands.getoutput(cmd)

    print "DONE"

def ref_fix_services(refroot):
    """ Disable certain services not necessary in vservers """

    print 'Turning off some services...'

    os.chdir(os.path.join(refroot, 'etc', 'init.d'))

    services = os.listdir('.')

    for service in services:
        if service in cfg.FEDORA_C2_NOT_SRVCS:
            continue
        else:
            onoff = ['off', 'on'][service in cfg.FEDORA_C2_SRVCS]
            cmd = '%s %s /sbin/chkconfig --level 2345 %s %s' % (cfg.CHROOT, refroot, service, onoff)
            print '  ', cmd
            pipe = os.popen('{ ' + cmd + '; } ', 'r', 0)
            s = pipe.read(1)
            while s:
                sys.stdout.write(s); sys.stdout.flush()
                s = pipe.read(1)
            pipe.close()

def ref_make_tabs(refroot):
    """ Make and /etc/fstab and an /etc/mtab """

    fname = os.path.join(refroot, 'etc', 'fstab')
    print 'Writing %s' % fname
    f = open(fname, 'w')
    f.write('/dev/hdv1  /       ext2    defaults  1       1\n')
    f.close()
    os.chmod(fname, 0644)

    fname = os.path.join(refroot, 'etc', 'mtab')
    print 'Writing %s' % fname
    f = open(fname, 'w')
    f.write('/dev/hdv1  /       ext2    rw        1       1\n')
    f.close()
    os.chmod(fname, 0644)

def ref_fix_halt(refroot):
    """ Replace halt with a simpler version so the
    server stops cleanly, also copy in vreboot """

    # XXX in alpha utils this is gone
    #fname = 'vreboot'
    #src = os.path.join(cfg.VSERVER_LIB, fname)
    #dst = os.path.join(refroot, 'sbin', fname)
    #print 'Copying %s to %s' % (src, dst)
    #shutil.copy(src, dst)

    fname = os.path.join(refroot, 'etc', 'init.d', 'halt')
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
            '/sbin/killall5 -9\n'
            '\n/sbin/halt -w\n')
    f.close()

def ref_fix_syslog(refroot):
    """ Remove references to klogd in syslog service """

    fname = os.path.join(refroot, 'etc', 'init.d', 'syslog')
    print 'Removing klogd from %s' % fname

    result = []

    for line in open(fname):

        if 'klogd' in line or 'kernel' in line:
            continue

        result.append(line)

    open(fname, 'w').writelines(result)

# def ref_fix_python(refroot):
#     print 'Making python 2.3 default'

#     cmd = 'rm %s' % os.path.join(refroot, 'usr/bin/python')
#     commands.getoutput(cmd)

#     cmd = 'ln %s %s' % (os.path.join(refroot, 'usr/bin/python2.3'),
#                         os.path.join(refroot, 'usr/bin/python'))
#     commands.getoutput(cmd)

def ref_make_libexec_oh(refroot):

    libexec_dir = os.path.join(refroot, 'usr/libexec/oh')
    
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

        shutil.copy(os.path.join(cfg.OH_MISC, short_name), dest_path)

        # why can't I do setuid with os.chmod?
        cmd = 'chmod 04755 %s' % dest_path
        commands.getoutput(cmd)

        vsutil.set_file_immutable_unlink(dest_path)

def ref_make_i18n(refroot):

    print 'Creating etc/sysconfig/i18n.'
    open(os.path.join(refroot, 'etc/sysconfig/i18n'), 'w').write(
        'LANG="en_US.UTF-8"\n'
        'SUPPORTED="en_US.UTF-8:en_US:en"\n'
        'SYSFONT="latarcyrheb-sun16"\n')

    s = 'localedef -i en_US -c -f UTF-8 en_US.UTF-8'
    print 'Running', s
    cmd = '%s %s %s' % (cfg.CHROOT, refroot, s)
    commands.getoutput(cmd)

def buildref(refroot, distroot):

    print 'Building a reference server at %s using packages in %s' % \
          (refroot, distroot)
    ref_make_root(refroot)
    ref_make_devs(refroot)
    ref_install_pkgs(refroot, distroot)
    ref_make_devs(refroot) # yes, again
    ref_fix_services(refroot)
    ref_make_tabs(refroot)
    ref_fix_halt(refroot)
    ref_fix_syslog(refroot)
#    ref_fix_python(refroot)
    ref_make_libexec_oh(refroot)
    ref_make_i18n(refroot)

    # enable shadow (I wonder why it isn't by default)
    cmd = '%s %s /usr/sbin/pwconv' % (cfg.CHROOT, refroot)
    s = commands.getoutput(cmd)

    # set flags
    fixflags(refroot)

def vserver_add_user(root, userid, passwd):
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
          (cfg.CHROOT, root, comment, passwd, userid)
    s = commands.getoutput(cmd)

def vserver_set_user_passwd(root, userid, passwd):
    """ Sets password for uerid. This method will guess whether
    the password is already md5 hashed or not (in which
    case it will hash it) """

    print 'Setting password for %s' % userid

    if passwd[0:3] == '$1$' and len(passwd) > 30:
        # this is a password hash (most likely)
        pass
    else:
        passwd = util.hash_passwd(passwd, md5=1)

    cmd = "%s %s /usr/sbin/usermod -p '%s' %s" % \
          (cfg.CHROOT, root, passwd, userid)
    s = commands.getoutput(cmd)
    
def vserver_make_hosts(root, hostname, ip):

    fname = os.path.join(root, 'etc', 'hosts')
    print 'Writing %s' % fname

    fqdn = hostname
    host = hostname.split('.')[0]

    open(fname, 'w').write('%s %s %s localhost' % (ip, fqdn, host))

    # /etc/sysconfig/network. at least xinetd service looks at it
    fname = os.path.join(root, 'etc', 'sysconfig', 'network')
    open(fname, 'w').write('NETWORKING=yes\nHOSTNAME=%s\n' % fqdn)

def vserver_make_resolv_conf(root, dns1, dns2=None, search=None):

    fname = os.path.join(root, 'etc', 'resolv.conf')
    print 'Writing %s' % fname

    f = open(fname, 'w')
    f.write('nameserver %s\n' % dns1)
    if dns2:
        f.write('nameserver %s\n' % dns2)
    if search:
        f.write('search %s\n' % search)

def vserver_make_motd(root):

    fname = os.path.join(root, 'etc', 'motd')
    print 'Writing %s' % fname

    # customize motd
    f = open(fname, 'w')
    f.write(cfg.MOTD)
    f.close()

def vserver_fixup_rc(root):

    # /etc/rc.d/rc needs to end with true

    rc = os.path.join(root, 'etc/rc.d/rc')
    lines = open(rc).readlines()
    if not lines[-1] == 'true\n':
        print 'Appending true to %s' % rc
        lines.append('\ntrue\n')
        open(rc, 'w').writelines(lines)
    else:
        print 'Not appending true to %s as it is already there' % rc

def vserver_config_sendmail(root, hostname):

    fname = os.path.join(root, 'etc', 'mail', 'local-host-names')
    print 'Writing %s' % fname

    fqdn = hostname
    domain = hostname.split('.', 1)[-1]

    f = open(fname, 'w')
    f.write('\n%s\n' % fqdn)
    f.write('%s\n' % domain)
    f.close()

    # up the load average so that sendmail does not refuse connections
    # even if the load is ridiculously high (this may not as critical
    # now that we've got vsched XXX)

    print 'Fixing RefuseLA in sendmail.cf'

    fname = os.path.join(root, 'etc', 'mail', 'sendmail.cf')
    lines = open(fname).readlines()

    for n in range(len(lines)):

        if lines[n].startswith('#O RefuseLA'):
            lines[n] = 'O RefuseLA=100\n'
        
    open(fname, 'w').writelines(lines)

def vserver_enable_imaps(root):

    # tell dovecot to listen to imaps and pops only

    print 'Configuring etc/dovecot.conf to only allow SSL imap and pop'

    protos = 'protocols = imaps pop3s\n'

    file = os.path.join(root, 'etc/dovecot.conf')

    set = 0
    lines = open(file).readlines()
    for n in range(len(lines)):
        stripped = lines[n].strip()
        if stripped.find('protocols') != -1:
            lines[n] = protos
            set = 1

    if not set:
        lines.append(protos)

    open(file, 'w').writelines(lines)

def vserver_stub_www_index_page(root):
    """ Create a stub default www page """

    fname = os.path.join(root, 'var', 'www', 'html', 'index.html')
    print 'Writing %s' % fname

    f = open(fname, 'w')
    f.write(cfg.INDEX_HTML)
    f.close()

def vserver_fix_services(root):
    ref_fix_services(root)

def vserver_disk_limit(root, xid, limit):

    dldb = os.path.join(cfg.VAR_DB_OH, 'disklimits')
    for line in open(dldb):
        if '-x %s' % xid in line:
            print 'NOT setting disk limits, they exist already for xid %s' % xid
            return

    print 'Setting disk limits:'

    dev = vsutil.guess_vserver_device()

    cmd = '%s -a -x %s -S 0,%s,0,%s,5 %s' % \
          (cfg.VDLIMIT, xid, limit, cfg.INODES_LIM, cfg.VSERVERS_ROOT)
    print ' ', cmd
    print commands.getoutput(cmd)

def vserver_bwidth_acct(name):

    # step is 1 minute, up to 300 seconds can be skept (heartbeat) before
    # data becomes unknown. Note that you should not increase this
    # value without adjusting the maximum value (12500000) because if the heartbeat
    # is large enough to where 4G can be transferred in that period,
    # everytime the counter is reset (e.g. reboot) rrd will treat it as overflow and
    # think you transferred 4G. Right now it always either exceeds the heartbeat
    # or the max, resulting in a NaN, which prevents the rrd overflow feature.
    # 1 minute averages are kept for 90 days,
    # 24hr averages are kept for 900 days
    # 1 minute max  is kept for 66 hours
    # 30 min max kept for 16 days
    # 24hr max kept for 900 days

    rrd = os.path.join(cfg.VAR_DB_OH, '%s.rrd' % name)

    if os.path.exists(rrd):
        print 'NOT creating %s, it exists already' % rrd
        return

    print 'Creating %s' % rrd

    cmd = 'rrdtool create %s -s 60 ' \
          'DS:in:COUNTER:300:0:12500000 ' \
          'DS:out:COUNTER:300:0:12500000 ' \
          'RRA:AVERAGE:0.5:1:129600 ' \
          'RRA:AVERAGE:0.5:1440:900 ' \
          'RRA:MAX:0.5:1:4000 ' \
          'RRA:MAX:0.5:30:800 '\
          'RRA:MAX:0.5:86400:900 ' % rrd

    commands.getoutput(cmd)

def vserver_iptables_rule(ip):

    print 'Adding iptables rules for bandwidth montoring'

    cmd = 'iptables -D INPUT -i %s -d %s' % (cfg.DFT_DEVICE, ip)
    commands.getoutput(cmd)
    cmd = 'iptables -A INPUT -i %s -d %s' % (cfg.DFT_DEVICE, ip)
    commands.getoutput(cmd)
    cmd = 'iptables -D OUTPUT -o %s -s %s' % (cfg.DFT_DEVICE, ip)
    commands.getoutput(cmd)
    cmd = 'iptables -A OUTPUT -o %s -s %s' % (cfg.DFT_DEVICE, ip)
    commands.getoutput(cmd)    

def vserver_make_ssl_cert(root, hostname):

    if os.path.exists(os.path.join(root, 'etc/httpd/conf/ssl.crt/.ohcert')):
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
    shutil.copy(os.path.join(d, 'server.crt'),  os.path.join(root, 'etc/httpd/conf/ssl.crt/server.crt'))
    shutil.copy(os.path.join(d, 'server.key'),  os.path.join(root, 'etc/httpd/conf/ssl.key/server.key'))
    os.chmod(os.path.join(root, 'etc/httpd/conf/ssl.crt/server.crt'), 0700)
    os.chmod(os.path.join(root, 'etc/httpd/conf/ssl.key/server.key'), 0700)
    commands.getoutput('cat %s %s > %s' % (os.path.join(d, 'server.crt'), os.path.join(d, 'server.key'),
                                           os.path.join(root, 'usr/share/ssl/certs/imapd.pem')))
    commands.getoutput('cat %s %s > %s' % (os.path.join(d, 'server.crt'), os.path.join(d, 'server.key'),
                                           os.path.join(root, 'usr/share/ssl/certs/ipop3d.pem')))
    commands.getoutput('cat %s %s > %s' % (os.path.join(d, 'server.crt'), os.path.join(d, 'server.key'),
                                           os.path.join(root, 'etc/webmin/miniserv.pem')))
    commands.getoutput('cat %s %s > %s' % (os.path.join(d, 'server.crt'), os.path.join(d, 'server.key'),
                                           os.path.join(root, 'usr/share/ssl/certs/dovecot.pem')))
    commands.getoutput('cat %s %s > %s' % (os.path.join(d, 'server.crt'), os.path.join(d, 'server.key'),
                                           os.path.join(root, 'usr/share/ssl/private/dovecot.pem')))
    s = commands.getoutput('rm -rf %s' % d)
    print s
    open(os.path.join(root, 'etc/httpd/conf/ssl.crt/.ohcert'), 'w').write('')
                                                            
def vserver_add_http_proxy(root):

    print 'Adding httpd config for panel proxy'
    f = open(os.path.join(root, 'etc/httpd/conf.d/openhosting.conf'), 'w')
    f.write(cfg.HTTPD_CONF)
    f.close()

def vserver_random_crontab(root):

    print 'Adding rndsleep and randomized crontab'

    fname = os.path.join(root, 'usr/local/bin/rndsleep')
    open(fname, 'w').write(cfg.RNDSLEEP)
    os.chmod(fname, 0755)

    open(os.path.join(root, 'etc/crontab'), 'w').write(cfg.CRONTAB)

def vserver_make_cvsroot(root):

    print 'Making a cvsroot'

    # normally we wouldn't care, but it makes webmin happy

    fname = os.path.join(root, 'usr/local/cvsroot')
    os.mkdir(fname)
    cmd = '%s %s cvs -d /usr/local/cvsroot init' % (cfg.CHROOT, root)
    s = commands.getoutput(cmd)

def vserver_disable_pam_limits(root):

    # pam_limits.so, which is enabled by default on fedora, will not
    # work in a vserver whose priority has been lowered using the
    # S_NICE configure option, which we do. pam_limits will cause
    # startup problems with sshd and other daemons:
    # http://www.paul.sladen.org/vserver/archives/200403/0277.html

    print 'Disabling pam limits'

    for pam in ['sshd', 'system-auth']:

        fname = os.path.join(root, 'etc/pam.d', pam)

        s = []
        for line in open(fname):
            if 'pam_limits' in line and line[0] != '#':
                s.append('#' + line)
            else:
                s.append(line)
        open(fname, 'w').write(''.join(s))

def vserver_webmin_passwd(root):

    # copy root password to webmin

    if not os.path.exists(os.path.join(root, 'etc/webmin')):
        print 'webmin not installed, skipping'
        return
    else:
        print 'Setting webmin password'
        
    shadow = os.path.join(root, 'etc/shadow')
    root_hash = ''
    for line in open(shadow):
        if line.startswith('root:'):
            root_hash = line.split(':')[1]
            break

    musers = os.path.join(root, 'etc/webmin/miniserv.users')
    open(musers, 'w').write('root:%s:0' % root_hash)
    os.chmod(musers, 0600)

def vserver_ohd_key(root, name):

    # create an ohd key, and add it to
    # allowed keys of the ohd user on the host

    keyfile = os.path.join(root, 'etc/ohd_key')

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

def vserver_fixup_libexec_oh(root):

    # This sets the right permissions for the files in
    # usr/libexec/oh

    print 'Setting flags in usr/libexec/oh'

    for file in ['traceroute',]:

        path = os.path.join(root, 'usr/libexec/oh/', file)
        vsutil.set_file_immutable_unlink(path)

def vserver_immutable_modules(root):

    # make lib/modules immutable. we already have a fake kernel
    # installed, but this will serve as a further deterrent against
    # installing kernels and/or modules. This flag can be unset from
    # within a vserver.

    print 'Making lib/modules immutable'

    cmd = 'chattr +i %s' % os.path.join(root, 'lib/modules')
    s = commands.getoutput(cmd)
    print s


## def vserver_make_symlink(root, xid):
    
##     # to hide the actual name of the vserver from other vservers (they
##     # can see it by looking at mounts in /proc/mount), the directory
##     # in which the vserver resides is renamed to the context_id rather
##     # than the vserver name, which in trun becomes a symlink. This way
##     # the /proc/mount shows stuff from which it is impossible to
##     # discern the vserver name. (Note that from ctx 0 you will still
##     # the symlink names, but from within a vserver you won't).

##     root = os.path.normpath(root) # strip trailing /

##     if not os.path.islink(root):
    
##         base = os.path.split(root)[0]

##         newname = os.path.join(base, xid)

##         print 'Renaming/symlinking %s -> %s' % (root, newname)

##         os.rename(root, newname)
##         os.symlink(os.path.basename(newname), root)

##     else:
##         print '%s already a symlink, leaving it alone' % root

def vserver_vroot_perms():

    # set perms on VSERVERS_ROOT
    # ...better safe than sorry...

    print 'Doing chmod 0000 %s, just in case' % cfg.VSERVERS_ROOT

    os.chmod(cfg.VSERVERS_ROOT, 0)


def customize(name, hostname, ip, xid, userid, passwd, disklim, dns=cfg.PRIMARY_IP):

    # first make a configuration
    vsutil.save_vserver_config(name, ip, xid, hostname=hostname)

    root = os.path.join(cfg.VSERVERS_ROOT, name)
    
    vserver_add_user(root, userid, passwd)
    vserver_set_user_passwd(root, 'root', passwd)
    vserver_make_hosts(root, hostname, ip)

    search = '.'.join(hostname.split('.')[1:])
    if '.' not in search:
        search = hostname
    vserver_make_resolv_conf(root, dns, search=search)

    vserver_fixup_rc(root)
    vserver_config_sendmail(root, hostname)
    vserver_enable_imaps(root)
    vserver_stub_www_index_page(root)
    vserver_make_motd(root)
    vserver_fix_services(root)
    vserver_disk_limit(root, xid, disklim)
    vserver_bwidth_acct(name, ip)
    vserver_iptables_rule(ip)
    vserver_make_ssl_cert(root, hostname)
    vserver_add_http_proxy(root)
    vserver_random_crontab(root)
    vserver_webmin_passwd(root)
    vserver_disable_pam_limits(root)
    vserver_ohd_key(root, name)
    vserver_fixup_libexec_oh(root)
    vserver_immutable_modules(root)
##    vserver_make_symlink(root, xid) # <- not relevant in 1.9.x
    vserver_vroot_perms()

    # ZZZ vsched
    
def match_path(path):
    """Return copy, touch pair based on config rules for this path"""

    # compile the config. if the patch begins with a /,
    # then assume that we want to match only at the
    # beginning, otherwise it's just a regular exp

    copy_exp, touch_exp, skip_exp = cfg.CLONE_RULES

    return copy_exp and not not copy_exp.search(path), \
           touch_exp and not not touch_exp.search(path), \
           skip_exp and not not skip_exp.search(path)

def copyown(src, dst):
    """Copy ownership"""
    st = os.lstat(src)
    if DRYRUN:
        print 'chown %d.%d %s' % (st.st_uid, st.st_gid, dst)
    else:
        os.lchown(dst, st.st_uid, st.st_gid)

bytes, lins, drs, syms, touchs, copys, devs = 0, 0, 0, 0, 0, 0, 0

def copy(src, dst, link=1, touch=0):
    """Copy a file, a directory or a link.
    When link is 1 (default), regular files will be hardlinked,
    as opposed to being copied. When touch is 1, only the file, but
    not the contents are copied (useful for logfiles).
    """

    global bytes, lins, drs, syms, touchs, copys, devs
    
    if os.path.islink(src):

        # if it is a symlink, always copy it
        # (no sense in trying to hardlink a symlink)

        if DRYRUN:
            print 'ln -s %s %s' % (os.readlink(src), dst)
        else:
            os.symlink(os.readlink(src), dst)
            copyown(src, dst)
        syms += 1

    elif os.path.isdir(src):

        # directories are also copied always

        if DRYRUN:
            s = os.stat(src)
            print 'mkdir %s; chmod 4%s %s' % (dst, oct(stat.S_IMODE(s.st_mode)), dst)
            copyown(src, dst)
        else:
            os.mkdir(dst)
            copyown(src, dst)
            shutil.copystat(src, dst)
        drs += 1

    elif os.path.isfile(src):

        # this a file, not a dir or symlink

        if touch:

            # means create a new file and copy perms
            
            if DRYRUN:
                print 'touch %s' % dst
            else:
                open(dst, 'w')
                copyown(src, dst)
                shutil.copystat(src, dst)

            touchs += 1
            
        elif link:

            # means we should hardlink
            
            if DRYRUN:
                print 'ln %s %s' % (src, dst)
            else:
                if vsutil.is_file_immutable_unlink(src):
                    os.link(src, dst)
                    lins += 1
                else:
                    # since it is not iunlink, copy it anyway
                    print 'Warning: not hardlinking %s because it is not iunlink' % src
                    shutil.copy(src, dst)
                    copyown(src, dst)
                    shutil.copystat(src, dst)
                    bytes += os.path.getsize(dst)
                    copys += 1
            
        else:

            # else copy it

            if DRYRUN:
                print 'cp -a %s %s' % (src, dst)
            else:
                shutil.copy(src, dst)
                copyown(src, dst)
                shutil.copystat(src, dst)
                bytes += os.path.getsize(dst)
                
            copys += 1

    else:

        # this is a special device?

        s = os.stat(src)
        if stat.S_ISBLK(s.st_mode) or stat.S_ISCHR(s.st_mode) \
           or stat.S_ISFIFO(s.st_mode):
            if DRYRUN:
                print "mknod %s %o %02x:%02x" % (dst, s.st_mode, os.major(s.st_rdev),
                                                 os.minor(s.st_rdev))
            else:
                os.mknod(dst, s.st_mode, os.makedev(os.major(s.st_rdev),
                                                    os.minor(s.st_rdev)))
                copyown(src, dst)
                shutil.copystat(src, dst)

            devs += 1

def clone(source, dest, pace=cfg.PACE[0]):

    # pace counter
    p = 0

    # this will strip trailing slashes
    source, dest = os.path.normpath(source), os.path.normpath(dest)

    print 'Cloning %s -> %s ... (this will take a while)' % (source, dest)

    # this will prevent some warnings
    os.chdir(cfg.VSERVERS_ROOT)
    
    #print source, dest
    copy(source, dest)

    for root, dirs, files in os.walk(source):

#        print root, dirs, files

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

#            print reldst, src, dst

            c, t, s = match_path(reldst)

            if not s:
                link = not c and not is_config(source, reldst)
                copy(src, dst, link=link, touch=t)

    print 'Done.'

    global bytes, lins, drs, syms, touchs, copys, devs
    print 'Bytes copied:'.ljust(20), bytes
    print 'Links created:'.ljust(20), lins
    print 'Dirs copied:'.ljust(20), drs
    print 'Symlinks copied:'.ljust(20), syms
    print 'Touched files:'.ljust(20), touchs
    print 'Copied files:'.ljust(20), copys
    print 'Devices:'.ljust(20), devs


def fixflags(refroot, pace=cfg.PACE[0]):

    # This routine sets immutable-unlink flags on all files,
    # except those that are marked as config (or mentioned at all)
    # in rpms

    # this will strip trailing slashes
    refroot = os.path.normpath(refroot)

    print 'Fixing flags in %s ... (this will take a while)' % refroot

    # pace counter
    p = 0

    # this will prevent some warnings related to chroot
    os.chdir(cfg.VSERVERS_ROOT)
    
    for root, dirs, files in os.walk(refroot):

#        print root, dirs, files

        for file in files + dirs:

            # do we need a pacing sleep?
            if pace and p >= pace:
                sys.stdout.write('.'); sys.stdout.flush()
                time.sleep(cfg.PACE[1])
                p = 0
            else:
                p += 1

            abspath = os.path.join(root, file)

            # reldst is the way it would look relative to refroot
            reldst = os.path.join(max(root[len(refroot):], '/'), file)
            
            c, t, s = match_path(reldst)

            if is_config(refroot, reldst) or c or t or s:
                pass
            else:
                if (not os.path.islink(abspath)) and (not os.path.isdir(abspath)):
                    # (do not make symlinks and dirs immutable)
                    vsutil.set_file_immutable_unlink(abspath)
            # NOTE that under no circumstances we *unset* the flag. This
            # is because e.g. usr/libexec/oh stuff must be iunlink, but
            # is not in an rpm.

    print 'Done.'

def addip(vserver, ip):

    # add a second ip address to a vserver
    
    vsutil.add_vserver_ip(vserver, ip)
    vserver_iptables_rule(ip)

rpm_cache = {}

def rpm_which_package(root, file):

    # find out which package owns file
    cmd = "%s %s rpm -qf '%s'" % (cfg.CHROOT, root, file)
    s = commands.getoutput(cmd)

    if 'not owned by any package' in s:
        return None
    else:
        return s


# now find out which files are in this package
def rpm_list_files(root, pkg):

    files = {}
    
    cmd = '%s %s rpm -ql --dump %s' % (cfg.CHROOT, root, pkg)
    pipe = os.popen('{ ' + cmd + '; } ', 'r')

    line = pipe.readline()
    while line:
        if 'is not installed' in line:
            return {}

        try:
            path, size, mtime, md5, mode, owner, group, isconfig, isdoc, rdev, symlink = \
                  line.split()
        except ValueError:
            # directories do not have md5
            path, size, mtime, mode, owner, group, isconfig, isdoc, rdev, symlink = \
                  line.split()

        # at this point isconf is all we care about, but more can be added
        files[path] = {'pkg':pkg, 'isconfig':int(isconfig)}

        line = pipe.readline()

    sts = pipe.close()                            

    return files

def rpm_file_isconfig(root, file):

    global rpm_cache

    if file not in rpm_cache:
        pkg = rpm_which_package(root, file)
        if not pkg:
            # assume it's config if not found, this will
            # make sure it is copied, not linked
            rpm_cache[file] = {'pkg':None, 'isconfig':1}
        else:
            rpm_cache.update(rpm_list_files(root, pkg))

            # it's possible that rpm thinks a package is of an rpm
            # but --dump won't list it... XXX why?
            if file not in rpm_cache:
                rpm_cache[file] = {'pkg':None, 'isconfig':1}

    return rpm_cache[file]['isconfig']

def is_config(root, file):
    return rpm_file_isconfig(root, file)


