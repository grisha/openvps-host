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

# $Id: Fedora.py,v 1.20 2007/06/07 20:52:21 grisha Exp $

# This is the base class for Fedora Core distributions.

import os
import sys
import commands
import tempfile
import shutil

from openvps.host import cfg
from RedHat import RedHat, RedHatBundle, RedHat_Bundle_base
import distro_util

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

    def get_desc(self):

        return "Fedora Core %d" % self.FC_VER


    def fixup_crontab(self):

        RedHat.fixup_crontab(self)

        # disable slocate
        os.chmod(os.path.join(self.vpsroot, 'etc/cron.daily/slocate.cron'), 0644)


class Fedora_Core_1(Fedora_Core):
    FC_VER = 1

#distro_util.register(Fedora_Core_1)


class Fedora_Core_2(Fedora_Core):
    FC_VER = 2

#distro_util.register(Fedora_Core_2)


class Fedora_Core_3(Fedora_Core):

    FC_VER = 3

    class _Bundle_base(RedHat_Bundle_base):

        DISTRO_DIR = 'Fedora/RPMS'

        name = 'base'
        desc = 'Fedora Core 3 Base'

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

            self.import_rpm_key()
            self.enable_shadow()

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

            print 'Enabling shadow and MD5 hashes'

            # enable shadow and md5 (I wonder why it isn't by default)
            cmd = '%s %s /usr/sbin/pwconv' % (cfg.CHROOT, self.vpsroot)
            s = commands.getoutput(cmd)
            cmd = '%s %s /usr/sbin/authconfig --kickstart --enablemd5 --enableshadow' % (cfg.CHROOT, self.vpsroot)
            s = commands.getoutput(cmd)


    class _Bundle_000_base2(RedHatBundle):

        name = 'base2'
        desc = 'Fedora Core 3 Base 2'
        
        packages = [
            'Glide3', 'Xaw3d', 'apr-util-devel', 'atk', 'atk-devel',
            'autoconf', 'automake', 'bind-chroot', 'binutils',
            'chkfontpath', 'cpp', 'curl', 'curl-devel', 'cvs',
            'cyrus-sasl-devel', 'db4-devel', 'dbh',
            'desktop-backgrounds-basic', 'distcache', 'dovecot',
            'e2fsprogs-devel', 'emacs', 'emacs-common', 'expat-devel',
            'fetchmail', 'fontconfig', 'fontconfig-devel',
            'fonts-xorg-base', 'freetype', 'freetype-devel', 'gcc',
            'gcc-c++', 'gd', 'gd-devel', 'gdbm-devel', 'glib-devel',
            'glib2-devel', 'glibc-devel', 'glibc-headers',
            'glibc-kernheaders', 'gtk2', 'gtk2-devel',
            'http://www.openvps.org/dist/misc/mirror/perl-Net-SSLeay-1.23-0.rhfc1.dag.i386.rpm',
            'http://www.openvps.org/dist/misc/mirror/proftpd-1.2.9-7.i386.rpm',
            'http://www.openvps.org/dist/misc/oh-bind-9.2.4-2.i386.rpm',
            'http://www.openvps.org/dist/misc/webmin-1.170-1_OH.noarch.rpm',
            'httpd-devel', 'krb5-devel', 'libc-client', 'libidn',
            'libstdc++-devel', 'libtool', 'libtool-libs', 'libungif',
            'libxfce4mcs', 'libxfce4mcs-devel', 'libxfce4util',
            'libxfcegui4', 'libxslt', 'lynx', 'mod_perl',
            'mod_perl-devel', 'mod_python', 'mod_ssl', 'mx', 'mysql',
            'mysql-devel', 'mysql-server', 'openldap-devel',
            'openssl-devel', 'pango', 'pango-devel', 'patch',
            'perl-DBD-MySQL', 'perl-DBD-Pg', 'perl-DBI',
            'perl-Digest-HMAC', 'perl-Digest-SHA1',
            'perl-HTML-Parser', 'perl-HTML-Tagset', 'perl-Net-DNS',
            'perl-Time-HiRes', 'perl-URI', 'perl-XML-Parser',
            'perl-libwww-perl', 'pkgconfig', 'postgresql',
            'postgresql-contrib', 'postgresql-devel',
            'postgresql-docs', 'postgresql-jdbc', 'postgresql-libs',
            'postgresql-pl', 'postgresql-python', 'postgresql-server',
            'postgresql-tcl', 'postgresql-test', 'python-devel',
            'rcs', 'rpm-build', 'rpm-devel', 'samba', 'samba-client',
            'samba-common', 'samba-swat', 'screen', 'spamassassin',
            'squid', 'startup-notification', 'switchdesk', 'tcl',
            'tcl-devel', 'telnet-server', 'tk', 'ttmkfdir',
            'vim-enhanced', 'vnc-server', 'webalizer',
            'xfce-mcs-manager', 'xfce-mcs-manager-devel',
            'xfce-mcs-plugins', 'xfce-utils', 'xfce4-panel',
            'xfdesktop', 'xffm', 'xffm-icons', 'xfwm4',
            'xfwm4-themes', 'xinetd', 'xinitrc', 'xorg-x11',
            'xorg-x11-Mesa-libGL', 'xorg-x11-Mesa-libGLU',
            'xorg-x11-devel', 'xorg-x11-font-utils', 'xorg-x11-libs',
            'xorg-x11-tools', 'xorg-x11-xauth', 'xorg-x11-xfs',
            'xterm', 'zlib-devel',
            ]

        def install(self):

            # call our super
            RedHatBundle.install(self)

            self.fix_vncserver()


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

    class _Bundle_100_PHP(RedHatBundle):

        name = 'php'
        desc = 'Fedora Core 3 PHP packages'
        
        packages = [ 'php', 'php-devel',
                     'php-domxml', 'php-imap', 'php-ldap',
                     'php-mysql', 'php-pear', 'php-pgsql',
                     'php-xmlrpc', 'php-gd',]

        def install(self):

            # call our super
            RedHatBundle.install(self)


    ### Fedora specific methods

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
                if 'pam_limits' in line and line[0] != '#':
                    s.append('#' + line)
                else:
                    s.append(line)
            open(fname, 'w').write(''.join(s))

    def fix_vncserver(self, name):

        # create a vncserver entry for the main account
        file = os.path.join(self.vpsroot, 'etc/sysconfig/vncservers')
        print 'Adding a %s vncserver in %s' % (name, file)

        open(file, 'a').write('VNCSERVERS="1:%s"\n' % name)

    def customize(self, name, xid, ip, userid, passwd, disklim, dns=cfg.PRIMARY_IP,
                  vpn_ip=None, vpn_mask='255.255.255.0'):

        # call super
        RedHat.customize(self, name, xid, ip, userid, passwd, disklim, dns,
                         vpn_ip, vpn_mask)

        self.enable_imaps()
        self.disable_pam_limits()
        self.fix_vncserver(name)

    def custcopy(self, source, name, userid, data={}, dns=cfg.PRIMARY_IP):

        xid = RedHat.custcopy(self, source, name, userid, data, dns)

        self.enable_imaps()
        self.disable_pam_limits()
        self.fix_vncserver(name)

        return xid

    def fixup_crontab(self):

        Fedora_Core.fixup_crontab(self)

        # disable weekly makewhatis
        os.chmod(os.path.join(self.vpsroot, 'etc/cron.weekly/00-makewhatis.cron'), 0644)

distro_util.register(Fedora_Core_3)

class Fedora_Core_4(Fedora_Core_3):

    FC_VER = 4

    class _Bundle_base(Fedora_Core_3._Bundle_base):

        name = 'base'
        desc = 'Fedora Core 4 Base'

        packages = [
            'SysVinit', 'acl', 'anacron', 'apr', 'apr-util', 'aspell',
            'aspell-en', 'at', 'attr', 'audit', 'audit-libs',
            'authconfig', 'basesystem', 'bash', 'bc', 'beecrypt',
            'http://www.openvps.org/dist/misc/bind-libs-9.3.1-8.OHFC4.i386.rpm',
            'http://www.openvps.org/dist/misc/bind-utils-9.3.1-8.OHFC4.i386.rpm',
            'bzip2', 'bzip2-libs',
            'chkconfig', 'coreutils', 'cpio', 'cracklib',
            'cracklib-dicts', 'crontabs', 'cyrus-sasl',
            'cyrus-sasl-md5', 'db4', 'desktop-file-utils',
            'diffutils', 'dos2unix', 'e2fsprogs', 'ed', 'elfutils',
            'elfutils-libelf', 'ethtool', 'expat', 'fedora-release',
            'file', 'filesystem', 'findutils', 'finger', 'ftp',
            'gawk', 'gdbm', 'glib', 'glib2', 'glibc', 'glibc-common',
            'gmp', 'gnupg', 'gpm', 'grep', 'groff', 'gzip', 'hesiod',
            'htmlview',
            'http://www.openvps.org/dist/misc/openvps-bogus-kernel-2.9.0-3.i386.rpm',
            'httpd', 'info', 'initscripts', 'iproute', 'iputils',
            'jwhois', 'krb5-libs', 'less', 'lftp', 'lha', 'libacl',
            'libattr', 'libgcc', 'libgcrypt', 'libgpg-error',
            'libjpeg', 'libpng', 'libselinux', 'libsepol',
            'libstdc++', 'libtermcap', 'libusb', 'libuser',
            'libwvstreams', 'libxml2', 'libxml2-python', 'logrotate',
            'logwatch', 'lrzsz', 'lsof', 'm4', 'mailcap', 'mailx',
            'make', 'man', 'man-pages', 'mingetty', 'mkinitrd',
            'mktemp', 'module-init-tools', 'mtr', 'nano', 'nc',
            'ncurses', 'neon', 'net-tools', 'newt', 'nscd',
            'nss_ldap', 'ntsysv', 'openldap', 'openssh',
            'openssh-clients', 'openssh-server', 'openssl', 'pam',
            'passwd', 'pax', 'pcre', 'pcre-devel', 'perl',
            'perl-Filter', 'pinfo', 'popt', 'portmap', 'procmail',
            'procps', 'psacct', 'psmisc', 'pyOpenSSL', 'python',
            'python-elementtree', 'python-sqlite',
            'python-urlgrabber', 'rdist', 'readline', 'redhat-menus',
            'rootfiles', 'rpm', 'rpm-libs', 'rpm-python', 'rsh',
            'rsync', 'sed', 'sendmail', 'setup', 'setuptool',
            'shadow-utils', 'slang', 'slocate', 'specspo', 'sqlite',
            'star', 'stunnel', 'sudo', 'symlinks', 'sysklogd', 'talk',
            'tar', 'tcp_wrappers', 'tcsh', 'telnet', 'termcap',
            'time', 'tmpwatch', 'traceroute', 'tzdata', 'unix2dos',
            'unzip', 'usermode', 'utempter', 'util-linux',
            'vim-common', 'vim-minimal', 'vixie-cron', 'wget',
            'which', 'words', 'yum', 'zip', 'zlib'
            ]

    class _Bundle_000_base2(RedHatBundle):

        name = 'base2'
        desc = 'Fedora Core 4 Base 2'
        
        packages = [
            'Xaw3d', 'apr-util-devel', 'atk', 'atk-devel', 'autoconf',
            'automake',
            'http://www.openvps.org/dist/misc/bind-chroot-9.3.1-8.OHFC4.i386.rpm',
            'binutils', 'chkfontpath',
            'cpp', 'curl', 'curl-devel', 'cvs', 'cyrus-sasl-devel',
            'db4-devel', 'distcache', 'dovecot', 'e2fsprogs-devel',
            'emacs', 'emacs-common', 'expat-devel', 'fetchmail',
            'fontconfig', 'fontconfig-devel', 'fonts-xorg-base',
            'freetype', 'freetype-devel', 'gcc', 'gcc-c++', 'gd',
            'gd-devel', 'gdbm-devel', 'glib-devel', 'glib2-devel',
            'glibc-devel', 'glibc-headers', 'glibc-kernheaders',
            'gtk2', 'gtk2-devel',
            'http://www.openvps.org/dist/misc/mirror/proftpd-1.2.9-7.i386.rpm',
            'http://www.openvps.org/dist/misc/bind-9.3.1-8.OHFC4.i386.rpm',
            'httpd-devel', 'krb5-devel', 'libc-client', 'libidn',
            'libstdc++-devel', 'libtool', 'libungif', 'libxslt',
            'lynx', 'mod_perl', 'mod_perl-devel', 'mod_python',
            'mod_ssl', 'mx', 'mysql', 'mysql-devel', 'mysql-server',
            'openldap-devel', 'openssl-devel', 'pango', 'pango-devel',
            'patch', 'perl-DBD-MySQL', 'perl-DBD-Pg', 'perl-DBI',
            'perl-Digest-HMAC', 'perl-Digest-SHA1',
            'perl-HTML-Parser', 'perl-HTML-Tagset', 'perl-Net-DNS',
            'perl-Time-HiRes', 'perl-URI', 'perl-XML-Parser',
            'perl-libwww-perl', 'pkgconfig', 'postgresql',
            'postgresql-contrib', 'postgresql-devel',
            'postgresql-docs', 'postgresql-jdbc', 'postgresql-libs',
            'postgresql-pl', 'postgresql-python', 'postgresql-server',
            'postgresql-tcl', 'postgresql-test', 'python-devel',
            'rcs', 'rpm-build', 'rpm-devel', 'samba', 'samba-client',
            'samba-common', 'samba-swat', 'screen', 'spamassassin',
            'squid', 'startup-notification', 'switchdesk', 'tcl',
            'tcl-devel', 'telnet-server', 'tk', 'ttmkfdir',
            'vim-enhanced', 'webalizer', 'xinetd', 'xinitrc',
            'xorg-x11', 'xorg-x11-Mesa-libGL', 'xorg-x11-Mesa-libGLU',
            'xorg-x11-devel', 'xorg-x11-font-utils', 'xorg-x11-libs',
            'xorg-x11-tools', 'xorg-x11-xauth', 'xorg-x11-xfs',
            'xterm', 'zlib-devel', 'apr-devel', 'libidn-devel',
            'fonts-xorg-75dpi', 'libtiff', 'libjpeg-devel',
            'libpng-devel', 'openssl097a', 'neon-devel',
            'sqlite-devel', 'perl-BSD-Resource', 'libselinux-devel',
            'cups-libs', 'freeglut', 'perl-Compress-Zlib'
            ]

    class _Bundle_010_Webmin(RedHatBundle):

        name = 'webmin'
        desc = 'OpenVPS-ized Webmin'
        
        packages = [
            'http://download.fedora.redhat.com/pub/fedora/linux/extras/4/i386/perl-Net-SSLeay-1.26-3.fc4.i386.rpm',
            'http://www.openvps.org/dist/misc/webmin-1.210-1_OH.noarch.rpm'
            ]

    class _Bundle_100_PHP(RedHatBundle):

        name = 'php'
        desc = 'Fedora Core 4 PHP packages'
        
        packages = [ 'php', 'php-devel',
                     'php-xml', 'php-imap', 'php-ldap',
                     'php-mysql', 'php-pear', 'php-pgsql',
                     'php-xmlrpc', 'php-gd',]

    class _Bundle_110_Xfce(RedHatBundle):

        name = 'xfce'
        desc = 'Fedora Core 4 Xfce packages'
        
        packages = [
            'desktop-backgrounds-basic',
            'http://download.fedora.redhat.com/pub/fedora/linux/extras/4/i386/dbh-1.0.24-3.fc4.i386.rpm',
            'http://download.fedora.redhat.com/pub/fedora/linux/extras/4/i386/libxfce4mcs-4.2.3-1.fc4.i386.rpm',
            'http://download.fedora.redhat.com/pub/fedora/linux/extras/4/i386/libxfce4mcs-devel-4.2.3-1.fc4.i386.rpm',
            'http://download.fedora.redhat.com/pub/fedora/linux/extras/4/i386/libxfce4util-4.2.3.2-1.fc4.i386.rpm',
            'http://download.fedora.redhat.com/pub/fedora/linux/extras/4/i386/libxfcegui4-4.2.3-2.fc4.i386.rpm',
            'http://download.fedora.redhat.com/pub/fedora/linux/extras/4/i386/xfce-mcs-manager-4.2.3-1.fc4.i386.rpm',
            'http://download.fedora.redhat.com/pub/fedora/linux/extras/4/i386/xfce-mcs-manager-devel-4.2.3-1.fc4.i386.rpm',
            'http://download.fedora.redhat.com/pub/fedora/linux/extras/4/i386/xfce-mcs-plugins-4.2.3-1.fc4.i386.rpm',
            'http://download.fedora.redhat.com/pub/fedora/linux/extras/4/i386/xfce-utils-4.2.3-1.fc4.i386.rpm',
            'http://download.fedora.redhat.com/pub/fedora/linux/extras/4/i386/xfce4-panel-4.2.3-1.fc4.i386.rpm',
            'http://download.fedora.redhat.com/pub/fedora/linux/extras/4/i386/xfdesktop-4.2.3-1.fc4.i386.rpm',
            'http://download.fedora.redhat.com/pub/fedora/linux/extras/4/i386/xffm-4.2.3-1.fc4.i386.rpm',
            'http://download.fedora.redhat.com/pub/fedora/linux/extras/4/i386/xfwm4-4.2.3.2-1.fc4.i386.rpm',
            'http://download.fedora.redhat.com/pub/fedora/linux/extras/4/i386/xfwm4-themes-4.2.3-1.fc4.noarch.rpm'
            ]

    class _Bundle_120_Xfce(RedHatBundle):

        name = 'vnc'
        desc = 'Fedora Core 4 VNC packages'
        
        packages = [
            'vnc-server'
            ]

    class _Bundle_130_subversion(RedHatBundle):

        name = 'subversion'
        desc = 'Fedora Core 4 Subversion packages'
        
        packages = [
            'subversion'
            ]

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

        Fedora_Core.fixup_crontab(self)

        # disable weekly makewhatis
        os.chmod(os.path.join(self.vpsroot, 'etc/cron.weekly/makewhatis.cron'), 0644)


distro_util.register(Fedora_Core_4)

