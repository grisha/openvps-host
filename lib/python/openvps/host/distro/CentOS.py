#
# Copyright 2007 OpenHosting, Inc.
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

# $Id: CentOS.py,v 1.18 2010/05/27 12:22:34 grisha Exp $

# This is the base class for Fedora Core distributions.

import os
import sys
import commands
import tempfile
import shutil

from openvps.host import cfg
from RedHat import RedHat, RedHatBundle, RedHat_Bundle_base
import distro_util


class CentOS(RedHat):

    CentOS_VER = '0'

    SERVICES =  ['crond', 'atd', 'httpd', 'sendmail', 'sshd',
                 'syslog', 'dovecot'] # no webmin
    
    def distro_version(self):

        # XXX
        # CentOS does not follow RedHat's convention in identifying
        # itself in its .discinfo file, the version simply said
        # "Final" in CentOS 5. So for now, we'll just take that
        # "Final" is CentOS 5
        
        rh_ver = RedHat.distro_version(self)
        try:
            if rh_ver:
                if rh_ver['name'] == 'Final':
                    if '5.2' in rh_ver['RPMS']:
                        rhel_ver = '5.2'
                    elif '5.3' in rh_ver['RPMS']:
                        rhel_ver = '5.3'
                    else:
                        rhel_ver = '5'
                    if rhel_ver == self.CentOS_VER:
                        return self.CentOS_VER
        except:
            return None
        
    def vps_version(self):
        rh_ver = RedHat.vps_version(self)
        try:
            if rh_ver and rh_ver.startswith('CentOS'):
                if rh_ver.split()[2] == self.CentOS_VER:
                    return self.CentOS_VER
        except:
            return None

    def get_desc(self):

        return "CentOS %s" % self.CentOS_VER

    def fixup_crontab(self):

        RedHat.fixup_crontab(self)

        # disable mlocate
        os.chmod(os.path.join(self.vpsroot, 'etc/cron.daily/mlocate.cron'), 0644)


class CentOS_5_0(CentOS):

    CentOS_VER = '5'

    class _Bundle_base(RedHat_Bundle_base):

        DISTRO_DIR = 'CentOS'

        SERVICES =  ['crond', 'atd', 'httpd', 'sendmail', 'sshd',
                     'syslog', 'dovecot'] # no webmin anymore

        name = 'base'
        desc = 'CentOS 5 Base'

        packages = [
            'SysVinit', 'acl', 'anacron', 'apr', 'apr-util', 'aspell',
            'aspell-en', 'at', 'attr', 'audit', 'audit-libs',
            'authconfig', 'basesystem', 'bash', 'bc', 'beecrypt',
            'bind-libs', 'bind-utils', 'bzip2', 'bzip2-libs',
            'centos-release', 'centos-release-notes', 'chkconfig',
            'coreutils', 'cpio', 'cracklib', 'cracklib-dicts',
            'crontabs', 'curl', 'cyrus-sasl', 'cyrus-sasl-lib',
            'cyrus-sasl-md5', 'db4', 'dbus', 'desktop-file-utils',
            'device-mapper', 'diffutils', 'dmraid', 'dos2unix',
            'e2fsprogs', 'e2fsprogs-libs', 'ed', 'elfutils',
            'elfutils-libelf', 'elfutils-libs', 'ethtool', 'expat',
            'file', 'filesystem', 'findutils', 'finger', 'ftp',
            'gawk', 'gdbm', 'glib2', 'glibc', 'glibc-common', 'gmp',
            'gnupg', 'gpm', 'grep', 'groff', 'gzip', 'hesiod',
            'htmlview',
            'http://www.openvps.org/dist/misc/openvps-bogus-kernel-2.9.0-3.i386.rpm',
            'httpd', 'info', 'initscripts', 'iproute', 'iputils',
            'jwhois', 'kpartx', 'krb5-libs', 'less', 'libacl',
            'libattr', 'libcap', 'libgcc', 'libgcrypt',
            'libgpg-error', 'libidn', 'libjpeg', 'libpng',
            'libselinux', 'libsepol', 'libstdc++', 'libtermcap',
            'libusb', 'libuser', 'libwvstreams', 'libxml2',
            'libxml2-python', 'logrotate', 'logwatch', 'lrzsz',
            'lsof', 'm2crypto', 'm4', 'mailcap', 'mailx', 'make',
            'man', 'man-pages', 'mcstrans', 'mingetty', 'mkinitrd',
            'mktemp', 'mlocate', 'module-init-tools', 'mtr', 'nano',
            'nash', 'nc', 'ncurses', 'neon', 'net-tools', 'newt',
            'nscd', 'nss_ldap', 'ntsysv', 'openldap', 'openssh',
            'openssh-clients', 'openssh-server', 'openssl', 'pam',
            'passwd', 'pax', 'pcre', 'pcre-devel', 'perl', 'pinfo',
            'popt', 'portmap', 'postgresql-libs', 'procmail',
            'procps', 'psacct', 'psmisc', 'pyOpenSSL', 'python',
            'python-elementtree', 'python-sqlite',
            'python-urlgrabber', 'rdist', 'readline', 'redhat-menus',
            'rhpl', 'rootfiles', 'rpm', 'rpm-libs', 'rpm-python',
            'rsh', 'rsync', 'ruby', 'ruby-libs', 'sed', 'sendmail',
            'setup', 'setuptool', 'shadow-utils', 'slang', 'specspo',
            'sqlite', 'star', 'stunnel', 'sudo', 'symlinks',
            'sysklogd', 'talk', 'tar', 'tcp_wrappers', 'tcsh',
            'telnet', 'termcap', 'time', 'tmpwatch', 'traceroute',
            'tzdata', 'unix2dos', 'unzip', 'usermode', 'util-linux',
            'vim-common', 'vim-minimal', 'vixie-cron', 'wget',
            'which', 'wireless-tools', 'words', 'yum',
            'yum-metadata-parser', 'zip', 'zlib']
        
        def install(self):

            # call our super
            RedHat_Bundle_base.install(self)

            self.enable_shadow()
            self.tracepath()

        def enable_shadow(self):

            print 'Enabling shadow and MD5 hashes'

            # enable shadow and md5 (I wonder why it isn't by default)
            cmd = '%s %s /usr/sbin/pwconv' % (cfg.CHROOT, self.vpsroot)
            s = commands.getoutput(cmd)
            cmd = '%s %s /usr/sbin/authconfig --kickstart --enablemd5 --enableshadow' % (cfg.CHROOT, self.vpsroot)
            s = commands.getoutput(cmd)

        def tracepath(self):

            print 'Symlinking traceroute to tracepath'

            cmd = '%s %s rm -f /bin/traceroute' % (cfg.CHROOT, self.vpsroot)
            s = commands.getoutput(cmd)
            cmd = '%s %s ln -s ./tracepath /bin/traceroute' % (cfg.CHROOT, self.vpsroot)
            s = commands.getoutput(cmd)


    class _Bundle_000_base2(RedHatBundle):

        DISTRO_DIR = 'CentOS'
        
        name = 'base2'
        desc = 'CentOS 5 Base 2'

        packages = [
            'Xaw3d', 'alsa-lib', 'apr-devel', 'apr-util-devel', 'atk',
            'atk-devel', 'audit-libs-python', 'autoconf', 'automake',
            'bind', 'bind-chroot', 'binutils', 'cairo', 'cairo-devel',
            'chkfontpath', 'cpp', 'cups-libs', 'curl-devel', 'cvs',
            'cyrus-sasl-devel', 'db4-devel', 'distcache', 'dovecot',
            'e2fsprogs-devel', 'elfutils-libelf-devel',
            'elfutils-libelf-devel-static', 'emacs', 'emacs-common',
            'expat-devel', 'fetchmail', 'fontconfig',
            'fontconfig-devel', 'freetype', 'freetype-devel', 'gcc',
            'gcc-c++', 'gd', 'gd-devel', 'gdbm-devel', 'giflib',
            'glib2-devel', 'glibc-devel', 'glibc-headers', 'gnutls',
            'gtk2', 'gtk2-devel', 'hicolor-icon-theme', 'httpd-devel',
            'imake', 'kernel-headers', 'krb5-devel', 'libFS',
            'libICE', 'libSM', 'libX11', 'libX11-devel', 'libXau',
            'libXau-devel', 'libXaw', 'libXcursor',
            'libXcursor-devel', 'libXdmcp', 'libXdmcp-devel',
            'libXext', 'libXext-devel', 'libXfixes',
            'libXfixes-devel', 'libXfont', 'libXft', 'libXft-devel',
            'libXi', 'libXi-devel', 'libXinerama',
            'libXinerama-devel', 'libXmu', 'libXpm', 'libXpm-devel',
            'libXrandr', 'libXrandr-devel', 'libXrender',
            'libXrender-devel', 'libXt', 'libXtst', 'libXxf86vm',
            'libart_lgpl', 'libc-client', 'libdrm', 'libfontenc',
            'libgcj', 'libgomp', 'libidn-devel', 'libjpeg-devel',
            'libpng-devel', 'libselinux-devel', 'libselinux-python',
            'libsemanage', 'libsepol-devel', 'libstdc++-devel',
            'libtiff', 'libtool', 'libutempter', 'libxslt', 'lynx',
            'ftp://rpmfind.net/linux/fedora/extras/development/i386/lzo-2.02-2.fc6.i386.rpm',
            'mesa-libGL', 'mesa-libGL-devel', 'mod_perl',
            'mod_perl-devel', 'mod_python', 'mod_ssl', 'mx', 'mysql',
            'mysql-devel', 'mysql-server', 'neon-devel',
            'ftp://rpmfind.net/linux/fedora/extras/6/i386/openvpn-2.1-0.17.rc2.fc6.i386.rpm',
            'openldap-devel', 'openssl-devel', 'openssl097a', 'pango',
            'pango-devel', 'patch', 'perl-Archive-Tar',
            'perl-BSD-Resource', 'perl-Compress-Zlib',
            'perl-DBD-MySQL', 'perl-DBD-Pg', 'perl-DBI',
            'perl-Digest-HMAC', 'perl-Digest-SHA1',
            'perl-HTML-Parser', 'perl-HTML-Tagset',
            'perl-IO-Socket-INET6', 'perl-IO-Socket-SSL',
            'perl-IO-Zlib', 'perl-Net-DNS', 'perl-Net-IP',
            'perl-Net-SSLeay', 'perl-Socket6', 'perl-URI',
            'perl-XML-Parser', 'perl-libwww-perl', 'pkgconfig',
            'policycoreutils', 'postgresql', 'postgresql-contrib',
            'postgresql-devel', 'postgresql-docs', 'postgresql-pl',
            'postgresql-python', 'postgresql-server',
            'postgresql-tcl', 'postgresql-test', 'python-devel',
            'rcs', 'rpm-build', 'rpm-devel', 'samba', 'samba-client',
            'samba-common', 'samba-swat', 'screen', 'spamassassin',
            'sqlite-devel', 'squid', 'startup-notification',
            'switchdesk', 'tcl', 'tcl-devel', 'telnet-server', 'tk',
            'ttmkfdir', 'vim-enhanced', 'vsftpd', 'webalizer',
            'xinetd', 'xorg-x11-filesystem', 'xorg-x11-font-utils',
            'xorg-x11-fonts-75dpi', 'xorg-x11-fonts-ISO8859-1-75dpi',
            'xorg-x11-fonts-base', 'xorg-x11-proto-devel',
            'xorg-x11-xauth', 'xorg-x11-xfs', 'xterm', 'zlib-devel']

    class _Bundle_010_Webmin(_Bundle_000_base2):

        name = 'webmin'
        desc = 'OpenVPS-ized Webmin'
        
        packages = [
            'http://www.openvps.org/dist/misc/webmin-1.340-1OH.noarch.rpm',
            ]

    class _Bundle_100_PHP(_Bundle_000_base2):

        name = 'php'
        desc = 'CentOS 5 PHP packages'
        
        packages = [
            'php', 'php-devel', 'php-cli', 'php-common', 'php-xml',
            'php-imap', 'php-ldap', 'php-mysql', 'php-pear',
            'php-pgsql', 'php-xmlrpc', 'php-gd', 'php-pdo',]

    class _Bundle_120_VNC(_Bundle_000_base2):

        name = 'vnc'
        desc = 'CentOS 5 VNC packages'
        
        packages = [
            'vnc-server'
            ]

    class _Bundle_130_subversion(_Bundle_000_base2):

        name = 'subversion'
        desc = 'CentOS 5 Subversion packages'
        
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

        for pam in ['atd', 'crond', 'login', 'remote', 'sshd',
                    'system-auth', 'vsftpd']:

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

        shutil.copy(os.path.join(d, 'server.crt'),  os.path.join(self.vpsroot, 'etc/pki/dovecot/certs/dovecot.pem'))
        shutil.copy(os.path.join(d, 'server.key'),  os.path.join(self.vpsroot, 'etc/pki/dovecot/private/dovecot.pem'))
        os.chmod(os.path.join(self.vpsroot, 'etc/pki/dovecot/certs/dovecot.pem'), 0700)
        os.chmod(os.path.join(self.vpsroot, 'etc/pki/dovecot/private/dovecot.pem'), 0700)

        commands.getoutput('cat %s %s > %s' % (os.path.join(d, 'server.crt'), os.path.join(d, 'server.key'),
                                               os.path.join(self.vpsroot, 'etc/webmin/miniserv.pem')))

        s = commands.getoutput('rm -rf %s' % d)
        print s
        open(os.path.join(self.vpsroot, 'etc/pki/tls/certs/.openvps-cert'), 'w').write('')

    def fixup_crontab(self):

        CentOS.fixup_crontab(self)

        # disable weekly makewhatis
        os.chmod(os.path.join(self.vpsroot, 'etc/cron.weekly/makewhatis.cron'), 0644)


class CentOS_5_2(CentOS_5_0):

    CentOS_VER = '5.2'

    class _Bundle_base(CentOS_5_0._Bundle_base):

        packages = [
            'SysVinit', 'acl', 'anacron', 'apr', 'apr-util', 'aspell',
            'aspell-en', 'at', 'attr', 'audit', 'audit-libs',
            'authconfig', 'basesystem', 'bash', 'bc', 'beecrypt',
            'bind-libs', 'bind-utils', 'bzip2', 'bzip2-libs',
            'centos-release', 'centos-release-notes', 'chkconfig',
            'coreutils', 'cpio', 'cracklib', 'cracklib-dicts',
            'crontabs', 'curl', 'cyrus-sasl', 'cyrus-sasl-lib',
            'cyrus-sasl-md5', 'db4', 'dbus', 'desktop-file-utils',
            'device-mapper', 'device-mapper-multipath', 'diffutils', 'dmraid', 'dos2unix',
            'e2fsprogs', 'e2fsprogs-libs', 'ed', 'elfutils',
            'elfutils-libelf', 'elfutils-libs', 'ethtool', 'expat',
            'file', 'filesystem', 'findutils', 'finger', 'ftp',
            'gawk', 'gdbm', 'glib2', 'glibc', 'glibc-common', 'gmp',
            'gnupg', 'gpm', 'grep', 'groff', 'gzip', 'hesiod',
            'htmlview',
            'http://www.openvps.org/dist/misc/openvps-bogus-kernel-2.9.0-3.i386.rpm',
            'httpd', 'info', 'initscripts', 'iproute', 'iputils',
            'jwhois', 'keyutils-libs', 'kpartx', 'krb5-libs', 'less', 'libacl',
            'libattr', 'libcap', 'libgcc', 'libgcrypt',
            'libgpg-error', 'libidn', 'libjpeg', 'libpng',
            'libselinux', 'libsepol', 'libstdc++', 'libsysfs', 'libtermcap',
            'libusb', 'libuser', 'libwvstreams', 'libxml2',
            'libxml2-python', 'logrotate', 'logwatch', 'lrzsz',
            'lsof', 'm2crypto', 'm4', 'mailcap', 'mailx', 'make',
            'man', 'man-pages', 'mcstrans', 'mingetty', 'mkinitrd',
            'mktemp', 'mlocate', 'module-init-tools', 'mtr', 'nano',
            'nash', 'nc', 'ncurses', 'neon', 'net-tools', 'newt',
            'nscd', 'nspr', 'nss', 'nss_ldap', 'ntsysv', 'openldap', 'openssh',
            'openssh-clients', 'openssh-server', 'openssl', 'pam',
            'passwd', 'pax', 'pcre', 'pcre-devel', 'perl', 'pinfo',
            'popt', 'portmap', 'postgresql-libs', 'procmail',
            'procps', 'psacct', 'psmisc', 'pyOpenSSL', 'python',
            'python-elementtree', 'python-iniparse', 'python-sqlite',
            'python-urlgrabber', 'rdist', 'readline', 'redhat-menus',
            'rhpl', 'rootfiles', 'rpm', 'rpm-libs', 'rpm-python',
            'rsh', 'rsync', 'ruby', 'ruby-libs', 'sed', 'sendmail',
            'setup', 'setuptool', 'shadow-utils', 'slang', 'specspo',
            'sqlite', 'star', 'stunnel', 'sudo', 'symlinks',
            'sysklogd', 'talk', 'tar', 'tcp_wrappers', 'tcsh',
            'telnet', 'termcap', 'time', 'tmpwatch', 'traceroute',
            'tzdata', 'unix2dos', 'unzip', 'usermode', 'util-linux',
            'vim-common', 'vim-minimal', 'vixie-cron', 'wget',
            'which', 'wireless-tools', 'words', 'yum',
            'yum-metadata-parser', 'zip', 'zlib']

    class _Bundle_000_base2(CentOS_5_0._Bundle_000_base2):

        packages = [
            'Xaw3d', 'alsa-lib', 'apr-devel', 'apr-util-devel', 'atk',
            'atk-devel', 'audit-libs-python', 'autoconf', 'automake',
            'bind', 'bind-chroot', 'binutils', 'cairo', 'cairo-devel',
            'chkfontpath', 'cpp', 'cups-libs', 'curl-devel', 'cvs',
            'cyrus-sasl-devel', 'db4-devel', 'distcache', 'dovecot',
            'e2fsprogs-devel', 'elfutils-libelf-devel',
            'elfutils-libelf-devel-static', 'emacs', 'emacs-common',
            'expat-devel', 'fetchmail', 'fontconfig',
            'fontconfig-devel', 'freetype', 'freetype-devel', 'gcc',
            'gcc-c++', 'gd', 'gd-devel', 'gdbm-devel', 'giflib',
            'glib2-devel', 'glibc-devel', 'glibc-headers', 'gnutls',
            'gtk2', 'gtk2-devel', 'hicolor-icon-theme', 'httpd-devel',
            'imake', 'kernel-headers', 'keyutils-libs-devel', 'krb5-devel', 'libFS',
            'libICE', 'libSM', 'libX11', 'libX11-devel', 'libXau',
            'libXau-devel', 'libXaw', 'libXcursor',
            'libXcursor-devel', 'libXdmcp', 'libXdmcp-devel',
            'libXext', 'libXext-devel', 'libXfixes',
            'libXfixes-devel', 'libXfont', 'libXft', 'libXft-devel',
            'libXi', 'libXi-devel', 'libXinerama',
            'libXinerama-devel', 'libXmu', 'libXpm', 'libXpm-devel',
            'libXrandr', 'libXrandr-devel', 'libXrender',
            'libXrender-devel', 'libXt', 'libXtst', 'libXxf86vm',
            'libart_lgpl', 'libc-client', 'libdrm', 'libfontenc',
            'libgcj', 'libgomp', 'libidn-devel', 'libjpeg-devel',
            'libpng-devel', 'libselinux-devel', 'libselinux-python',
            'libsemanage', 'libsepol-devel', 'libstdc++-devel',
            'libtiff', 'libtool', 'libutempter', 'libxslt', 'lynx',
            'http://rpmfind.net/linux/fedora/releases/8/Everything/x86_64/os/Packages/lzo-2.02-3.fc8.x86_64.rpm',
            'mesa-libGL', 'mesa-libGL-devel', 'mod_perl',
            'mod_perl-devel', 'mod_python', 'mod_ssl', 'mx', 'mysql',
            'mysql-devel', 'mysql-server', 'neon-devel',
            'http://rpmfind.net/linux/fedora/releases/8/Everything/x86_64/os/Packages/openvpn-2.1-0.19.rc4.fc7.x86_64.rpm',
            'openldap-devel', 'openssl-devel', 'openssl097a', 'pango',
            'pango-devel', 'patch', 'perl-Archive-Tar',
            'perl-BSD-Resource', 'perl-Compress-Zlib',
            'perl-DBD-MySQL', 'perl-DBD-Pg', 'perl-DBI',
            'perl-Digest-HMAC', 'perl-Digest-SHA1',
            'perl-HTML-Parser', 'perl-HTML-Tagset',
            'perl-IO-Socket-INET6', 'perl-IO-Socket-SSL',
            'perl-IO-Zlib', 'perl-Net-DNS', 'perl-Net-IP',
            'perl-Net-SSLeay', 'perl-Socket6', 'perl-URI',
            'perl-XML-Parser', 'perl-libwww-perl', 'pkgconfig',
            'policycoreutils', 'postgresql', 'postgresql-contrib',
            'postgresql-devel', 'postgresql-docs', 'postgresql-pl',
            'postgresql-python', 'postgresql-server',
            'postgresql-tcl', 'postgresql-test', 'python-devel',
            'rcs', 'rpm-build', 'rpm-devel', 'samba', 'samba-client',
            'samba-common', 'samba-swat', 'screen', 'spamassassin',
            'sqlite-devel', 'squid', 'startup-notification',
            'switchdesk', 'tcl', 'tcl-devel', 'telnet-server', 'tk',
            'ttmkfdir', 'vim-enhanced', 'vsftpd', 'webalizer',
            'xinetd', 'xorg-x11-filesystem', 'xorg-x11-font-utils',
            'xorg-x11-fonts-75dpi', 'xorg-x11-fonts-ISO8859-1-75dpi',
            'xorg-x11-fonts-base', 'xorg-x11-proto-devel',
            'xorg-x11-xauth', 'xorg-x11-xfs', 'xterm', 'zlib-devel']

class CentOS_5_3(CentOS_5_2):
    CentOS_VER = '5.3'

class CentOS_5_4(CentOS_5_3):
    CentOS_VER = '5.4'

class CentOS_5_5(CentOS_5_4):
    CentOS_VER = '5.5'

distro_util.register(CentOS_5_0)
distro_util.register(CentOS_5_2)
distro_util.register(CentOS_5_3)
distro_util.register(CentOS_5_4)
distro_util.register(CentOS_5_5)

