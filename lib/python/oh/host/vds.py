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

# $Id: vds.py,v 1.15 2004/09/28 01:42:54 grisha Exp $

""" VDS related functions """

import os
import sys
import stat
import shutil
import re
import commands
import tempfile
import time

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
        os.chdir(distroot)
        
        print "Installing base packages STEP I..."
        cmd = 'rpm --root %s -Uvh %s' % (root, ' '.join(cfg.FEDORA_C1_PKGS_BASE_I))
        pipe = os.popen('{ ' + cmd + '; } ', 'r', 0)
        s = pipe.read(1)
        while s:
            sys.stdout.write(s); sys.stdout.flush()
            s = pipe.read(1)
        pipe.close()

        # another mising dir
        os.mkdir(os.path.join(root, 'usr', 'src', 'redhat'))

        print "Installing packages STEP II..."
        #cmd = 'rpm --root %s -Uvh --nodeps %s' % (root, ' '.join(cfg.FEDORA_C1_PKGS['ADDL']))
        cmd = 'rpm --root %s -Uvh %s' % (root, ' '.join(cfg.FEDORA_C1_PKGS_BASE_II))
        pipe = os.popen('{ ' + cmd + '; } ', 'r', 0)
        s = pipe.read(1)
        while s:
            sys.stdout.write(s); sys.stdout.flush()
            s = pipe.read(1)
        pipe.close()


        if cfg.FEDORA_C1_PKGS_ADDL:
        
            print "Installing additional packages..."
            #cmd = 'rpm --root %s -Uvh --nodeps %s' % (root, ' '.join(cfg.FEDORA_C1_PKGS['ADDL']))
            cmd = 'rpm --root %s -Uvh %s' % (root, ' '.join(cfg.FEDORA_C1_PKGS_ADDL))
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
        if service in cfg.FEDORA_C1_NOT_SRVCS:
            continue
        else:
            onoff = ['off', 'on'][service in cfg.FEDORA_C1_SRVCS]
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

    fname = 'vreboot'
    src = os.path.join(cfg.VSERVER_LIB, fname)
    dst = os.path.join(refroot, 'sbin', fname)
    print 'Copying %s to %s' % (src, dst)
    shutil.copy(src, dst)

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

def ref_fix_python(refroot):
    print 'Making python 2.3 default'

    cmd = 'rm %s' % os.path.join(refroot, 'usr/bin/python')
    commands.getoutput(cmd)

    cmd = 'ln %s %s' % (os.path.join(refroot, 'usr/bin/python2.3'),
                        os.path.join(refroot, 'usr/bin/python'))
    commands.getoutput(cmd)

def ref_make_libexec_oh(refroot):

    libexec_dir = os.path.join(refroot, 'usr/libexec/oh')
    
    print 'Making %s' % libexec_dir
    os.mkdir(libexec_dir)

    print 'Copying ping, traceroute, mount and umount there'


    for path, short_name in [('bin/ping', 'ping'),
                             ('bin/traceroute', 'traceroute'),
                             ('bin/mount', 'mount'),
                             ('bin/umount', 'umount'),]:

        # move the originals into libexec/oh
        dest_path = os.path.join(libexec_dir, src)

        shutil.move(os.path.join(refroot, short_name), dest_path)

        if not vsutil.is_file_immutable_link(dest_path):
            vsutil.set_file_immutable_link(dest_path)

        # now place our custom in their path
        dest_path = os.path.join(refroot, 'bin/ping')

        shutil.copy(os.path.join(cfg.OH_MISC, short_name), dest_path)

        # why can't I do setuid with os.chmod?
        cmd = 'chmod 04755 %s' % dest_path
        commands.getoutput(cmd)

        if not vsutil.is_file_immutable_link(dest_path):
            vsutil.set_file_immutable_link(dest_path)

def ref_make_i18n(refroot):

    open(os.path.join(refroot, 'etc/sysconfig/i18n'), 'w').write(
        'LANG="en_US.UTF-8"'
        'SUPPORTED="en_US.UTF-8:en_US:en"'
        'SYSFONT="latarcyrheb-sun16"')

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
    ref_fix_python(refroot)
    ref_make_libexec_oh(refroot)
    ref_make_i18n(refroot)

    # enable shadow (I wonder why it isn't by default)
    cmd = '%s %s /usr/sbin/pwconv' % (cfg.CHROOT, refroot)
    s = commands.getoutput(cmd)

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
    
def make_vserver_config(name, ip, xid, hostname=None, dev='eth0'):

    fname = os.path.join(cfg.ETC_VSERVERS, '%s.conf' % name)
    print 'Making config file %s' % fname

    if not hostname:
        hostname = name

    # make a primitive vserver config
    s = 'IPROOT=%s\n' % ip
    s += 'IPROOTMASK=255.255.255.255\n'
    s += 'IPROOTBCAST=%s\n' % ip
    s += 'IPROOTDEV=%s\n' % dev
    s += 'S_HOSTNAME=%s\n' % hostname
    s += 'ONBOOT=yes\n'
    s += "#ULIMIT='%s'\n" % cfg.DFT_ULIMIT
    s += 'S_CONTEXT=%s\n' % xid
    s += 'S_NICE=%s\n' % cfg.DFT_NICE

    open(fname, 'w').write(s)

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

def vserver_config_sendmail(root, hostname):

    fname = os.path.join(root, 'etc', 'mail', 'local-host-names')
    print 'Writing %s' % fname

    fqdn = hostname
    domain = hostname.split('.', 1)[-1]

    f = open(fname, 'w')
    f.write('\n%s\n' % fqdn)
    f.write('%s\n' % domain)
    f.close()

def vserver_enable_imaps(root):

    print 'Enabling IMAPS and POP3S'

    imaps_path = os.path.join(root, 'etc', 'xinetd.d', 'imaps')
    s = open(imaps_path).read()
    s = s.replace('= yes', '= no')
    open(imaps_path, 'w').write(s)

    imaps_path = os.path.join(root, 'etc', 'xinetd.d', 'pop3s')
    s = open(imaps_path).read()
    s = s.replace('= yes', '= no')
    open(imaps_path, 'w').write(s)

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

    cmd = '%s -x %s -v %s' % \
          (os.path.join(cfg.CQ_TOOLS, 'cqhadd'), xid, dev)
    print ' ', cmd
    commands.getoutput(cmd)

    cmd = '%s -x %s -S 0,%s,0,%s,5 -v %s' % \
          (os.path.join(cfg.CQ_TOOLS, 'cqdlim'), xid, cfg.INODES_LIM,
           limit, dev)
    print ' ', cmd
    commands.getoutput(cmd)

def vserver_bwidth_acct(name, ip):

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

    print 'Adding iptables rules for bandwidth montoring'

    cmd = 'iptables -D INPUT -i eth0 -d %s' % ip
    commands.getoutput(cmd)
    cmd = 'iptables -A INPUT -i eth0 -d %s' % ip
    commands.getoutput(cmd)
    cmd = 'iptables -D OUTPUT -o eth0 -s %s' % ip
    commands.getoutput(cmd)
    cmd = 'iptables -A OUTPUT -o eth0 -s %s' % ip
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
    s = 'from="127.0.0.1",command="/usr/bin/sudo /usr/local/oh/misc/ohdexec %s" %s' % (name, key)

    open(ohdkeys, 'a+').write(s)

def vserver_fixup_libexec_oh(root):

    # This sets the right permissions for the files in
    # usr/libexec/oh

    print 'Setting flags in usr/libexec/oh'

    png = os.path.join(root, 'usr/libexec/oh/ping')
    tr = os.path.join(root, 'usr/libexec/oh/traceroute')

    if not vsutil.is_file_immutable_link(png):
        vsutil.set_file_immutable_link(png)
    if not vsutil.is_file_immutable_link(tr):
        vsutil.set_file_immutable_link(tr)

def vserver_make_symlink(root, xid):
    
    # to hide the actual name of the vserver from other vservers (they
    # can see it by looking at mounts in /proc/mount), the directory
    # in which the vserver resides is renamed to the context_id rather
    # than the vserver name, which in trun becomes a symlink. This way
    # the /proc/mount shows stuff from which it is impossible to
    # discern the vserver name. (Note that from ctx 0 you will still
    # the symlink names, but from within a vserver you won't).

    root = os.path.normpath(root) # strip trailing /

    if not os.path.islink(root):
    
        base = os.path.split(root)[0]

        newname = os.path.join(base, xid)

        print 'Renaming/symlinking %s -> %s' % (root, newname)

        os.rename(root, newname)
        os.symlink(os.path.basename(newname), root)

    else:
        print '%s already a symlink, leaving it alone' % root


def vserver_vroot_perms():

    # set perms on VSERVERS_ROOT
    # ...better safe than sorry...

    print 'Doing chmod 0000 %s, just in case' % cfg.VSERVERS_ROOT

    os.chmod(cfg.VSERVERS_ROOT, 0)


def customize(name, hostname, ip, xid, userid, passwd, disklim, dns):

    # first make a configuration
    make_vserver_config(name, ip, xid, hostname=hostname)

    root = os.path.join(cfg.VSERVERS_ROOT, name)
    
    vserver_add_user(root, userid, passwd)
    vserver_set_user_passwd(root, 'root', passwd)
    vserver_make_hosts(root, hostname, ip)

    search = '.'.join(hostname.split('.')[1:])
    if '.' not in search:
        search = hostname
    vserver_make_resolv_conf(root, dns, search=search)

    vserver_config_sendmail(root, hostname)
    vserver_enable_imaps(root)
    vserver_stub_www_index_page(root)
    vserver_make_motd(root)
    vserver_fix_services(root)
    vserver_disk_limit(root, xid, disklim)
    vserver_bwidth_acct(name, ip)
    vserver_make_ssl_cert(root, hostname)
    vserver_add_http_proxy(root)
    vserver_random_crontab(root)
    vserver_webmin_passwd(root)
    vserver_disable_pam_limits(root)
    vserver_ohd_key(root, name)
    vserver_fixup_libexec_oh(root)
    vserver_make_symlink(root, xid)
    vserver_vroot_perms()
    
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

bytes, lins, dirs, syms, touchs, copys, devs = 0, 0, 0, 0, 0, 0, 0

def copy(src, dst, link=1, touch=0):
    """Copy a file, a directory or a link.
    When link is 1 (default), regular files will be hardlinked,
    as opposed to being copied. When touch is 1, only the file, but
    not the contents are copied (useful for logfiles).
    """

    global bytes, lins, dirs, syms, touchs, copys, devs
    
    if os.path.islink(src):

        if DRYRUN:
            print 'ln -s %s %s' % (os.readlink(src), dst)
        else:
            os.symlink(os.readlink(src), dst)
            copyown(src, dst)
        syms += 1

    elif os.path.isdir(src):

        if DRYRUN:
            s = os.stat(src)
            print 'mkdir %s; chmod 4%s %s' % (dst, oct(stat.S_IMODE(s.st_mode)), dst)
            copyown(src, dst)
        else:
            os.mkdir(dst)
            copyown(src, dst)
            shutil.copystat(src, dst)
        dirs += 1

    elif os.path.isfile(src):

        if touch:
            if DRYRUN:
                print 'touch %s' % dst
            else:
                open(dst, 'w')
                copyown(src, dst)
                shutil.copystat(src, dst)

            touchs += 1
            
        elif link:
            if DRYRUN:
                print 'ln %s %s' % (src, dst)
            else:
                os.link(src, dst)
                if not vsutil.is_file_immutable_link(dst):
                    vsutil.set_file_immutable_link(dst)

            lins += 1
            
        else:

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

def clone(source, dest, pace=1000):

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
                time.sleep(2)
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

rpm_cache = {}

def rpm_which_package(root, file):

    # find out which package owns file
    cmd = '%s %s rpm -qf %s' % (cfg.CHROOT, root, file)
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


