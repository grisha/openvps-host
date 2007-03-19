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

# $Id: CentOS.py,v 1.1 2007/03/19 20:08:03 grisha Exp $

# This is the base class for Fedora Core distributions.

import os
import sys
import commands
import tempfile
import shutil

from openvps.host import cfg
from RedHat import RedHat, RedHatBundle, RedHat_Bundle_base
import distro_util


class RHEL(RedHat):

    RHEL_VER = '0'

    def distro_version(self):
        rh_ver = RedHat.distro_version(self)
        try:
            if rh_ver:
                if rh_ver['name'].startswith('Red Hat Enterprise'):
                    rhel_ver = rh_ver['name'].split()[-1]
                    if rhel_ver == self.RHEL_VER:
                        return self.RHEL_VER
        except:
            return None
        
    def vps_version(self):
        rh_ver = RedHat.vps_version(self)
        try:
            if rh_ver and rh_ver.startswith('Red Hat Enterprise'):
                if rh_ver.split()[6] == self.RHEL_VER:
                    return self.RHEL_VER
        except:
            return None

    def get_desc(self):

        return "RHEL %s" % self.RHEL_VER


    def fixup_crontab(self):

        RedHat.fixup_crontab(self)

        # disable mlocate
        os.chmod(os.path.join(self.vpsroot, 'etc/cron.daily/mlocate.cron'), 0644)


class RHEL_4_92(RHEL):

    RHEL_VER = '4.92'

    class _Bundle_base(RedHat_Bundle_base):

        DISTRO_DIR = 'RHEL'

        name = 'base'
        desc = 'RHEL 4 Base'

        packages = [
            'SysVinit', 'acl', 'anacron', 'apr', 'apr-util', 'aspell',
            'aspell-en', 'at', 'attr', 'audit', 'audit-libs',
            'authconfig', 'basesystem', 'bash', 'bc', 'beecrypt',
            # XXX
            #'http://www.openvps.org/dist/misc/bind-libs-9.3.1-8.OHFC4.i386.rpm',
            #'http://www.openvps.org/dist/misc/bind-utils-9.3.1-8.OHFC4.i386.rpm',
            'dbus',
            'device-mapper', 'elfutils-libs', 'curl', 'libidn', 'mcstrans', 'libcap', 'dmraid', 'kpartx', 'nash', 'm2crypto', 'wireless-tools', 'yum-metadata-parser',
            'bzip2', 'bzip2-libs',
            'chkconfig', 'coreutils', 'cpio', 'cracklib',
            'cracklib-dicts', 'crontabs', 'cyrus-sasl', 'cyrus-sasl-lib',
            'cyrus-sasl-md5', 'db4', 'desktop-file-utils',
            'diffutils', 'dos2unix', 'e2fsprogs', 'e2fsprogs-libs', 'ed', 'elfutils',
            'elfutils-libelf', 'ethtool', 'expat', 'redhat-release',
            'file', 'filesystem', 'findutils', 'finger', 'ftp',
            'gawk', 'gdbm', 'glib2', 'glibc', 'glibc-common',
            'gmp', 'gnupg', 'gpm', 'grep', 'groff', 'gzip', 'hesiod',
            'htmlview',
            'http://www.openvps.org/dist/misc/openvps-bogus-kernel-2.9.0-3.i386.rpm',
            'httpd', 'info', 'initscripts', 'iproute', 'iputils',
            'jwhois', 'krb5-libs', 'less', #'lftp',
            'libacl',
            'libattr', 'libgcc', 'libgcrypt', 'libgpg-error',
            'libjpeg', 'libpng', 'libselinux', 'libsepol',
            'libstdc++', 'libtermcap', 'libusb', 'libuser',
            'libwvstreams', 'libxml2', 'libxml2-python', 'logrotate',
            'logwatch', 'lrzsz', 'lsof', 'm4', 'mailcap', 'mailx',
            'make', 'man', 'man-pages', 'mingetty', 'mkinitrd', 'mlocate',
            'mktemp', 'module-init-tools', 'mtr', 'nano', 'nc',
            'ncurses', 'neon', 'net-tools', 'newt', 'nscd',
            'nss_ldap', 'ntsysv', 'openldap', 'openssh',
            'openssh-clients', 'openssh-server', 'openssl', 'pam',
            'passwd', 'pax', 'pcre', 'pcre-devel', 'perl',
            'pinfo', 'popt', 'portmap', 'postgresql-libs', 'procmail', 'libgcrypt',
            'procps', 'psacct', 'psmisc', 'pyOpenSSL', 'python',
            'python-elementtree', 'python-sqlite',
            'python-urlgrabber', 'rdist', 'readline', 'redhat-menus', 'rhpl',
            'rootfiles', 'rpm', 'rpm-libs', 'rpm-python', 'rsh',
            'rsync', 'sed', 'sendmail', 'setup', 'setuptool',
            'shadow-utils', 'slang', 'specspo', 'sqlite',
            'star', 'stunnel', 'sudo', 'symlinks', 'sysklogd', 'talk',
            'tar', 'tcp_wrappers', 'tcsh', 'telnet', 'termcap',
            'time', 'tmpwatch', 'traceroute', 'tzdata', 'unix2dos',
            'unzip', 'usermode', 'util-linux',
            'vim-common', 'vim-minimal', 'vixie-cron', 'wget',
            'which', 'words', 'yum', 'zip', 'zlib'
            ]

    class _Bundle_000_base2(RedHatBundle):

        name = 'base2'
        desc = 'RHEL 4 Base 2'
        
        packages = [
            'Xaw3d', 'apr-util-devel', 'atk', 'atk-devel', 'autoconf',
            'automake',
            #'http://www.openvps.org/dist/misc/bind-chroot-9.3.1-8.OHFC4.i386.rpm',
            'binutils', 'chkfontpath',
            'cpp', 'curl-devel', 'cvs', 'cyrus-sasl-devel',
            'db4-devel', 'distcache', 'dovecot', 'e2fsprogs-devel',
            'emacs', 'emacs-common', 'expat-devel', 'fetchmail',
            'fontconfig', 'fontconfig-devel', #'fonts-xorg-base',
            'freetype', 'freetype-devel', 'gcc', 'gcc-c++', 'gd',
            'gd-devel', 'gdbm-devel', 'glib2-devel',
            'glibc-devel', 'glibc-headers', 'kernel-headers', #'glibc-kernheaders',
            'gtk2', 'gtk2-devel',
            'http://www.openvps.org/dist/misc/mirror/proftpd-1.2.9-7.i386.rpm',
            #'http://www.openvps.org/dist/misc/bind-9.3.1-8.OHFC4.i386.rpm',
            'httpd-devel', 'krb5-devel', 'libc-client', #'libidn',
            'libstdc++-devel', 'libtool', #'libungif',
            'libxslt',
            'lynx', 'mod_perl', 'mod_perl-devel', 'mod_python',
            'mod_ssl', 'mx', 'mysql', 'mysql-devel', 'mysql-server',
            'openldap-devel', 'openssl-devel', 'pango', 'pango-devel',
            'patch', 'perl-DBD-MySQL', 'perl-DBD-Pg', 'perl-DBI',
            'perl-Digest-HMAC', 'perl-Digest-SHA1',
            'perl-HTML-Parser', 'perl-HTML-Tagset', 'perl-Net-DNS',
            #'perl-Time-HiRes',
            'perl-URI', 'perl-XML-Parser',
            'perl-libwww-perl', 'pkgconfig', 'postgresql',
            'postgresql-contrib', 'postgresql-devel',
            'postgresql-docs', #'postgresql-jdbc',
            #'postgresql-libs',
            'postgresql-pl', 'postgresql-python', 'postgresql-server',
            'postgresql-tcl', 'postgresql-test', 'python-devel',
            'rcs', 'rpm-build', 'rpm-devel', 'samba', 'samba-client',
            'samba-common', 'samba-swat', 'screen', 'spamassassin',
            'squid', 'startup-notification', 'switchdesk', 'tcl',
            'tcl-devel', 'telnet-server', 'tk', 'ttmkfdir',
            'vim-enhanced', 'webalizer', 'xinetd', #'xinitrc',
            #'xorg-x11',
            #'xorg-x11-Mesa-libGL', 'xorg-x11-Mesa-libGLU',
            #'xorg-x11-devel',
            'xorg-x11-font-utils', #'xorg-x11-libs',
            #'xorg-x11-tools',
            'xorg-x11-xauth', 'xorg-x11-xfs',
            'xorg-x11-fonts-base', 'xorg-x11-fonts-75dpi',
            'xterm', 'zlib-devel', 'apr-devel', 'libidn-devel',
            #'fonts-xorg-75dpi',
            'libtiff', 'libjpeg-devel',
            'libpng-devel', 'openssl097a', 'neon-devel',
            'sqlite-devel', 'perl-BSD-Resource', 'libselinux-devel',
            'cups-libs', #'freeglut',
            'perl-Compress-Zlib',
            'gnutls',
            'libXmu',
            'libXrender',
            'libXfont',
            'libXau',
            'libfontenc',
            'libX11',
            'libXft',
            'libICE',
            'libXfixes', 'libXfixes-devel',
            'libXext',
            'cairo',
            'libSM',
            'libXpm',
            'libXt',
            'giflib',
            'xorg-x11-fonts-ISO8859-1-75dpi',
            'imake',
            'libgomp',
            'libX11-devel',
            'libXpm-devel',
            'hicolor-icon-theme',
            'libXcursor',
            'libXi',
            'libXinerama',
            'libXrandr',
            'cairo-devel',
            'libXcursor-devel',
            'libXext-devel',
            'libXi-devel',
            'libXinerama-devel',
            'libXrandr-devel',
            #'openssl',
            'redhat-release-notes',
            'libXft-devel',
            'libXrender-devel',
            'perl-Net-IP',
            'libgcj',
            'elfutils-libelf-devel',
            'perl-Archive-Tar',
            'perl-IO-Socket-INET6',
            'perl-IO-Socket-SSL',
            'xorg-x11-filesystem',
            'libFS',
            'libXaw',
            'policycoreutils',
            'libutempter',
            'libsepol-devel',
            'libXdmcp',
            'xorg-x11-proto-devel',
            'libXau-devel',
            'libXdmcp-devel',
            'libXtst',
            'libart_lgpl',
            'perl-IO-Zlib',
            'perl-Socket6',
            'perl-Net-SSLeay',
            'alsa-lib',
            'audit-libs-python',
            'libselinux-python',
            'libsemanage',
            'mesa-libGL-devel',
            'mesa-libGL',
            'libXxf86vm',
            'libdrm',
            #'postgresql-libs',
            #'libidn',
            #'curl'
            ]

##     class _Bundle_010_Webmin(RedHatBundle):

##         name = 'webmin'
##         desc = 'OpenVPS-ized Webmin'
        
##         packages = [
##             'http://download.fedora.redhat.com/pub/fedora/linux/extras/4/i386/perl-Net-SSLeay-1.26-3.fc4.i386.rpm',
##             'http://www.openvps.org/dist/misc/webmin-1.210-1_OH.noarch.rpm'
##             ]

    class _Bundle_100_PHP(RedHatBundle):

        name = 'php'
        desc = 'RHEL 4 PHP packages'
        
        packages = [ 'php', 'php-devel', 'php-cli', 'php-common',
                     'php-xml', 'php-imap', 'php-ldap',
                     'php-mysql', 'php-pear', 'php-pgsql',
                     'php-xmlrpc', 'php-gd', 'php-pdo',]

    class _Bundle_120_VNC(RedHatBundle):

        name = 'vnc'
        desc = 'RHEL 4 VNC packages'
        
        packages = [
            'vnc-server'
            ]

    class _Bundle_130_subversion(RedHatBundle):

        name = 'subversion'
        desc = 'RHEL 4 Subversion packages'
        
        packages = [
            'subversion'
            ]

    def enable_imaps(self):

        # tell dovecot to listen to imaps and pops only

        print 'Configuring etc/dovecot.conf to only allow SSL imap and pop'

        protos = 'protocols = imaps pop3s\n'

        file = os.path.join(self.vpsroot, 'etc/dovecot.conf')

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

    def disable_pam_limits(self):

        # pam_limits.so, which is enabled by default on fedora, will not
        # work in a vserver whose priority has been lowered using the
        # S_NICE configure option, which we do. pam_limits will cause
        # startup problems with sshd and other daemons:
        # http://www.paul.sladen.org/vserver/archives/200403/0277.html

        print 'Disabling pam limits'

        for pam in ['sshd', 'system-auth']:

            fname = os.path.join(self.vpsroot, 'etc/pam.d', pam)

            s = []
            for line in open(fname):
                if (('pam_limits' in line and line[0] != '#') or
                    ('pam_loginuid' in line and line[0] != '#')):
                    s.append('#' + line)
                else:
                    s.append(line)
            open(fname, 'w').write(''.join(s))

    def fix_vncserver(self, name):

        # create a vncserver entry for the main account
        file = os.path.join(self.vpsroot, 'etc/sysconfig/vncservers')
        print 'Adding a %s vncserver in %s' % (name, file)

        open(file, 'a').write('VNCSERVERS="1:%s"\n' % name)

    def customize(self, name, xid, ip, userid, passwd, disklim, dns=cfg.PRIMARY_IP):

        # call super
        RedHat.customize(self, name, xid, ip, userid, passwd, disklim, dns=cfg.PRIMARY_IP)

        self.enable_imaps()
        self.disable_pam_limits()
        self.fix_vncserver(name)

    def custcopy(self, source, name, userid, data={}, dns=cfg.PRIMARY_IP):

        xid = RedHat.custcopy(self, source, name, userid, data, dns)

        self.enable_imaps()
        self.disable_pam_limits()
        self.fix_vncserver(name)

        return xid

    def make_ssl_cert(self, hostname):

        if os.path.exists(os.path.join(self.vpsroot, 'etc/pki/tls/certs/.openvps-cert')):
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
        shutil.copy(os.path.join(d, 'server.crt'),  os.path.join(self.vpsroot, 'etc/pki/tls/certs/localhost.crt'))
        shutil.copy(os.path.join(d, 'server.key'),  os.path.join(self.vpsroot, 'etc/pki/tls/private/localhost.key'))
        os.chmod(os.path.join(self.vpsroot, 'etc/pki/tls/certs/localhost.crt'), 0700)
        os.chmod(os.path.join(self.vpsroot, 'etc/pki/tls/private/localhost.key'), 0700)


        shutil.copy(os.path.join(d, 'server.crt'),  os.path.join(self.vpsroot, 'etc/pki/dovecot/dovecot.pem'))
        shutil.copy(os.path.join(d, 'server.key'),  os.path.join(self.vpsroot, 'etc/pki/dovecot/private/dovecot.pem'))
        os.chmod(os.path.join(self.vpsroot, 'etc/pki/dovecot/dovecot.pem'), 0700)
        os.chmod(os.path.join(self.vpsroot, 'etc/pki/dovecot/private/dovecot.pem'), 0700)

        commands.getoutput('cat %s %s > %s' % (os.path.join(d, 'server.crt'), os.path.join(d, 'server.key'),
                                               os.path.join(self.vpsroot, 'etc/webmin/miniserv.pem')))

        s = commands.getoutput('rm -rf %s' % d)
        print s
        open(os.path.join(self.vpsroot, 'etc/pki/tls/certs/.openvps-cert'), 'w').write('')

    def fixup_crontab(self):

        RHEL.fixup_crontab(self)

        # disable weekly makewhatis
        os.chmod(os.path.join(self.vpsroot, 'etc/cron.weekly/makewhatis.cron'), 0644)


distro_util.register(RHEL_4_92)

# ZZZ
# look at enable_shadow and other stuff in FC3
