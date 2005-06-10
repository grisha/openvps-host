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

# $Id: Fedora.py,v 1.4 2005/06/10 21:36:59 grisha Exp $

# This is the base class for Fedora Core distributions.

import os
import sys
import commands

from openvps.host import cfg
from RedHat import RedHat, RedHatBundle, RedHat_Bundle_base
import util

class Fedora_Core(RedHat):

    FC_VER = 0

    def distro_version(self):

        rh_ver = RedHat.distro_version(self)
        try:
            if rh_ver:
                fc_ver = rh_ver['name'].split()[-1]
                if int(fc_ver) == self.FC_VER:
                    return self.FC_VER
        except:
            return None
        
    def vps_version(self):

        rh_ver = RedHat.vps_version(self)
        try:
            if rh_ver and rh_ver.startswith('Fedora Core release'):
                if int(rh_ver.split()[3]) == self.FC_VER:
                    return self.FC_VER
        except:
            return None

class Fedora_Core_1(Fedora_Core):
    FC_VER = 1

util.register(Fedora_Core_1)


class Fedora_Core_2(Fedora_Core):
    FC_VER = 2

util.register(Fedora_Core_2)


class Fedora_Core_3(Fedora_Core):

    FC_VER = 3

    class _Bundle_base(RedHat_Bundle_base):

        desc  = 'Fedora Core 3 Base'

        packages = [ 'SysVinit', 'acl', 'anacron', 'apr', 'apr-devel',
            'apr-util', 'ash', 'aspell', 'aspell-en', 'at', 'attr',
            'authconfig', 'basesystem', 'bash', 'bc', 'beecrypt',
            'bind-libs', 'bind-utils', 'bzip2', 'bzip2-libs',
            'chkconfig', 'coreutils', 'cpio', 'cracklib',
            'cracklib-dicts', 'crontabs', 'cups-libs', 'cyrus-sasl',
            'cyrus-sasl-md5', 'db4', 'diffutils', 'dos2unix',
            'e2fsprogs', 'ed', 'elfutils', 'elfutils-libelf',
            'ethtool', 'expat', 'fedora-release', 'file',
            'filesystem', 'findutils', 'finger', 'ftp', 'gawk',
            'gdbm', 'glib', 'glib2', 'glibc', 'glibc-common', 'gmp',
            'gnupg', 'gpm', 'grep', 'groff', 'gzip', 'hesiod',
            'htmlview',
            'http://www.openvps.org/dist/misc/openvps-bogus-kernel-2.9.0-2.i386.rpm',
            'httpd', 'httpd-suexec', 'info', 'initscripts', 'iproute',
            'iputils', 'jwhois', 'krb5-libs', 'less', 'lftp', 'lha',
            'libacl', 'libattr', 'libgcc', 'libgcrypt',
            'libgpg-error', 'libjpeg', 'libpng', 'libselinux',
            'libsepol', 'libstdc++', 'libtermcap', 'libtiff',
            'libuser', 'libwvstreams', 'libxml2', 'libxml2-python',
            'logrotate', 'logwatch', 'lrzsz', 'lsof', 'm4', 'mailcap',
            'mailx', 'make', 'man', 'man-pages', 'mingetty',
            'mkinitrd', 'mktemp', 'module-init-tools', 'mtr', 'nano',
            'nc', 'ncurses', 'net-tools', 'newt', 'nscd', 'nss_ldap',
            'ntsysv', 'openldap', 'openssh', 'openssh-clients',
            'openssh-server', 'openssl', 'pam', 'passwd', 'pax',
            'pcre', 'pcre-devel', 'perl', 'perl-Filter', 'pinfo',
            'popt', 'portmap', 'procmail', 'procps', 'psacct',
            'psmisc', 'pyOpenSSL', 'python', 'rdist', 'readline',
            'redhat-menus', 'rootfiles', 'rpm', 'rpm-libs',
            'rpm-python', 'rsh', 'rsync', 'sed', 'sendmail', 'setup',
            'setuptool', 'shadow-utils', 'slang', 'slocate',
            'specspo', 'star', 'stunnel', 'sudo', 'symlinks',
            'sysklogd', 'talk', 'tar', 'tcp_wrappers', 'tcsh',
            'telnet', 'termcap', 'time', 'tmpwatch', 'traceroute',
            'tzdata', 'unix2dos', 'unzip', 'usermode', 'utempter',
            'util-linux', 'vim-common', 'vim-minimal', 'vixie-cron',
            'wget', 'which', 'words', 'yum', 'zip', 'zlib', ]
        
        def install(self):

            # make some base directories that are required before anything
            # works
        
            os.mkdir(os.path.join(self.vpsroot, 'var'))
            os.mkdir(os.path.join(self.vpsroot, 'var', 'lib'))
            os.mkdir(os.path.join(self.vpsroot, 'var', 'lib', 'rpm'))
            os.mkdir(os.path.join(self.vpsroot, 'usr'))
            os.mkdir(os.path.join(self.vpsroot, 'usr', 'src'))
            os.mkdir(os.path.join(self.vpsroot, 'usr', 'src', 'redhat'))
            os.mkdir(os.path.join(self.vpsroot, 'proc'))

            # call our super
            RedHat_Bundle_base.install(self)

            # fixups?

            
    
    class _Bundle_base2(RedHatBundle):
        
        desc = 'Fedora Core 3 Base 2'
        
        packages = [ 'Glide3', 'Xaw3d', 'apr-util-devel', 'atk',
                     'atk-devel', 'autoconf', 'automake',
                     'bind-chroot', 'binutils', 'chkfontpath', 'cpp',
                     'curl', 'curl-devel', 'cvs', 'cyrus-sasl-devel',
                     'db4-devel', 'dbh', 'desktop-backgrounds-basic',
                     'distcache', 'dovecot', 'e2fsprogs-devel',
                     'emacs', 'emacs-common', 'expat-devel',
                     'fetchmail', 'fontconfig', 'fontconfig-devel',
                     'fonts-xorg-base', 'freetype', 'freetype-devel',
                     'gcc', 'gcc-c++', 'gd', 'gd-devel', 'gdbm-devel',
                     'glib-devel', 'glib2-devel', 'glibc-devel',
                     'glibc-headers', 'glibc-kernheaders', 'gtk2',
                     'gtk2-devel',
                     'http://www.openvps.org/dist/misc/mirror/perl-Net-SSLeay-1.23-0.rhfc1.dag.i386.rpm',
                     'http://www.openvps.org/dist/misc/mirror/proftpd-1.2.9-7.i386.rpm',
                     'http://www.openvps.org/dist/misc/oh-bind-9.2.4-2.i386.rpm',
                     'http://www.openvps.org/dist/misc/webmin-1.170-1_OH.noarch.rpm',
                     'httpd-devel', 'krb5-devel', 'libc-client',
                     'libidn', 'libstdc++-devel', 'libtool',
                     'libtool-libs', 'libungif', 'libxfce4mcs',
                     'libxfce4mcs-devel', 'libxfce4util',
                     'libxfcegui4', 'libxslt', 'lynx', 'mod_perl',
                     'mod_perl-devel', 'mod_python', 'mod_ssl', 'mx',
                     'mysql', 'mysql-devel', 'mysql-server',
                     'openldap-devel', 'openssl-devel', 'pango',
                     'pango-devel', 'patch', 'perl-DBD-MySQL',
                     'perl-DBD-Pg', 'perl-DBI', 'perl-Digest-HMAC',
                     'perl-Digest-SHA1', 'perl-HTML-Parser',
                     'perl-HTML-Tagset', 'perl-Net-DNS',
                     'perl-Time-HiRes', 'perl-URI', 'perl-XML-Parser',
                     'perl-libwww-perl', 'php', 'php-devel',
                     'php-domxml', 'php-imap', 'php-ldap',
                     'php-mysql', 'php-pear', 'php-pgsql',
                     'php-xmlrpc', 'php-gd', 'pkgconfig',
                     'postgresql', 'postgresql-contrib',
                     'postgresql-devel', 'postgresql-docs',
                     'postgresql-jdbc', 'postgresql-libs',
                     'postgresql-pl', 'postgresql-python',
                     'postgresql-server', 'postgresql-tcl',
                     'postgresql-test', 'python-devel', 'rcs',
                     'rpm-build', 'rpm-devel', 'samba',
                     'samba-client', 'samba-common', 'samba-swat',
                     'screen', 'spamassassin', 'squid',
                     'startup-notification', 'switchdesk', 'tcl',
                     'tcl-devel', 'telnet-server', 'tk', 'ttmkfdir',
                     'vim-enhanced', 'vnc-server', 'webalizer',
                     'xfce-mcs-manager', 'xfce-mcs-manager-devel',
                     'xfce-mcs-plugins', 'xfce-utils', 'xfce4-panel',
                     'xfdesktop', 'xffm', 'xffm-icons', 'xfwm4',
                     'xfwm4-themes', 'xinetd', 'xinitrc', 'xorg-x11',
                     'xorg-x11-Mesa-libGL', 'xorg-x11-Mesa-libGLU',
                     'xorg-x11-devel', 'xorg-x11-font-utils',
                     'xorg-x11-libs', 'xorg-x11-tools',
                     'xorg-x11-xauth', 'xorg-x11-xfs', 'xterm',
                     'zlib-devel', ]

        def install(self):

            # call our super
            RedHatBundle.install(self)

            self.fix_vncserver()
            self.import_rpm_key()
            self.enable_shadow()


        def fix_vncserver(self):

            # make vnc server start the lightweight xfce
            # instead of twm

            file = os.path.join(self.vpsroot, 'usr/bin/vncserver')

            print 'Fixing up %s to start the lightweight xfce4' % file

            lines = open(file).readlines()
            for n in range(len(lines)):
                if 'twm' in lines[n]:
                    lines[n] = lines[n].replace('twm', 'startxfce4')

            open(file, 'w').writelines(lines)


        def import_rpm_key(self):

            path = os.path.join(self.vpsroot, 'usr/share/doc/fedora-release-3/RPM-GPG-KEY')
            print 'Importing RPM GPG key: %s' % path
            cmd = 'rpm -r %s --import %s' % (self.vpsroot, path)
            commands.getoutput(cmd)

            path = os.path.join(self.vpsroot, 'usr/share/doc/fedora-release-3/RPM-GPG-KEY-fedora')
            print 'Importing RPM GPG key: %s' % path
            cmd = 'rpm -r %s --import %s' % (self.vpsroot, path)
            commands.getoutput(cmd)


        def enable_shadow(self):

            # enable shadow and md5 (I wonder why it isn't by default)
            cmd = '%s %s /usr/sbin/pwconv' % (cfg.CHROOT, self.vpsroot)
            s = commands.getoutput(cmd)
            cmd = '%s %s /usr/sbin/authconfig --kickstart --enablemd5 --enableshadow' % (cfg.CHROOT, self.vpsroot)
            s = commands.getoutput(cmd)


util.register(Fedora_Core_3)


