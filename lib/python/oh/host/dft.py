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

# $Id: dft.py,v 1.2 2004/03/26 02:40:40 grisha Exp $

""" Configuration Defaults """

import os, sys

DEBUG = 0

PREFIX = '/usr/local/'
OH_DIR = os.path.join(PREFIX, 'oh')
OH_MISC = os.path.join(OH_DIR, 'misc')

CONFIG_DIR = os.path.join(PREFIX, 'etc')
CONFIG_FILE = os.path.join(CONFIG_DIR, 'ohhost.conf')

OHCHKPWD = os.path.join(PREFIX, 'sbin', 'ohchkpwd')

ETC_VSERVERS = '/etc/vservers'
VSERVER_LIB = '/usr/local/lib/util-vserver'

VSERVERS_ROOT = '/vservers'

CQ_TOOLS = '/usr/local/cq-tools-0.06'
VSERVER_STAT = '/usr/local/sbin/vserver-stat'
VSERVER = '/usr/local/sbin/vserver'

VAR_DB_OH = '/var/db/oh'

BACKUP = '/backup'

# default inodes per vserever allowed
INODES_LIM = 50000

# When cloning a reference server, these rules dictate
# what is done. Default action is to hardlink, unless
# any of the paths below match:
#  'copy' - copy files
#  'touch' - copy just the file, not its data
#  'skip' - ignore it
#
# NOTE that the config will compile these and turn CLONE_RULES
# into a triple of (copy, touch, skip) re objects.

CLONE_RULES = {
    'copy' : ['/etc'], #['/etc', '/var', '/root'],
    'touch' : ['/var/log', '/var/run', '\.bash_history'],
    'skip' : ['ssh_host_', '.pem$'] # ['/dev']
    }

# location of chroot command
CHROOT = '/usr/sbin/chroot'

RRDTOOL = '/usr/bin/rrdtool'

# The /etc/motd file
MOTD = """
    Welcome to OpenHosting!    

    For technical support, please refer to
    http://www.openhosting.com/support
    or e-mail us at support@openhosting.com

    """

INDEX_HTML = """
    <html>
      <title>OpenHosting, Inc.</title>
      <br><br><br><br>
      <center>
        <a href="http://www.openhosting.com/" border=0>
        <image src="http://www.openhosting.com/images/logo.gif" border=0></a>
        <br><br>
        <span style="color: #747474;"><h3>This site is under construction!<h3></style> 
      </center>
      </html>
      """ # keep emacs happy "

# Default ulimits. Note that this is per pocess, not per vserver,
# so it doesn't really mean much.
DFT_ULIMIT = '-HS -u 1000 -v 500000'
DFT_NICE = '9' # not as nice as default (10), but nice

# services we want enabled (everything else is disabled)
FEDORA_C1_SRVCS =  ['crond', 'atd', 'httpd', 'sendmail', 'sshd',
                   'syslog', 'xinetd']
# these aren't really services, but are in /etc/init.d
FEDORA_C1_NOT_SRVCS = ['functions', 'killall', 'halt', 'single']

# This a dictionary with two lists: BASE and ADDL.
# BASE is installed first, then ADDTL.

FEDORA_C1_PKGS = {
    'BASE' : [
    'chkconfig-1.3.9-1.i386.rpm',
    'glibc-2.3.2-101.i386.rpm',
    'glibc-common-2.3.2-101.i386.rpm',
    'coreutils-5.0-24.i386.rpm',
    'termcap-11.0.1-17.noarch.rpm',
    'libtermcap-2.0.8-36.i386.rpm',
    'ethtool-1.8-2.1.i386.rpm',
    'tzdata-2003d-1.noarch.rpm',
    'beecrypt-3.0.1-0.20030630.1.i386.rpm',
    'elfutils-libelf-0.89-2.i386.rpm',
    'tcp_wrappers-7.6-34.as21.1.i386.rpm',
    'gpm-1.20.1-38.i386.rpm',
    '4Suite-1.0-0.0.a3.i386.rpm',
#    'MAKEDEV-3.3.8-2.i386.rpm',
    'PyXML-0.8.3-1.i386.rpm',
    'SysVinit-2.85-5.i386.rpm',
    'a2ps-4.13b-30.i386.rpm',
    'alchemist-1.0.27-3.i386.rpm',
    'anacron-2.3-29.i386.rpm',
    'ash-0.3.8-15.i386.rpm',
    'at-3.1.8-46.1.i386.rpm',
    'audiofile-0.2.3-7.i386.rpm',
    'authconfig-4.3.8-1.i386.rpm',
    'basesystem-8.0-2.noarch.rpm',
    'bash-2.05b-31.i386.rpm',
    'bzip2-1.0.2-10.i386.rpm',
    'bzip2-libs-1.0.2-10.i386.rpm',
    'cpio-2.5-5.i386.rpm',
    'cracklib-2.7-23.i386.rpm',
    'cracklib-dicts-2.7-23.i386.rpm',
    'crontabs-1.10-5.noarch.rpm',
    'cyrus-sasl-2.1.15-6.i386.rpm',
    'cyrus-sasl-md5-2.1.15-6.i386.rpm',
    'db4-4.1.25-14.i386.rpm',
    'dev-3.3.8-2.i386.rpm',
    'diffutils-2.8.1-9.i386.rpm',
    'dosfstools-2.8-11.i386.rpm',
    'e2fsprogs-1.34-1.i386.rpm',
    'ed-0.2-34.i386.rpm',
    'fam-2.6.8-12.i386.rpm',
    'file-4.02-2.i386.rpm',
    'filesystem-2.2.1-5.i386.rpm',
    'findutils-4.1.7-17.i386.rpm',
    'libacl-2.2.7-2.i386.rpm',
    'libgcc-3.3.2-1.i386.rpm',
    'freetype-2.1.4-5.i386.rpm',
    'gawk-3.1.3-3.i386.rpm',
    'gdbm-1.8.0-21.i386.rpm',
    'glib-1.2.10-11.i386.rpm',
    'glib2-2.2.3-1.1.i386.rpm',
    'gnupg-1.2.2-3.i386.rpm',
    'grep-2.5.1-17.i386.rpm',
    'groff-1.18.1-29.i386.rpm',
    'gzip-1.3.3-11.i386.rpm',
    'indexhtml-1-2.noarch.rpm',
    'info-4.5-2.i386.rpm',
    'initscripts-7.42-1.i386.rpm',
    'iputils-20020927-9.1.i386.rpm',
    'less-378-11.1.i386.rpm',
    'libcap-1.10-16.i386.rpm',
    'libghttp-1.0.9-8.i386.rpm',
    'libjpeg-6b-29.i386.rpm',
    'libmng-1.0.4-4.i386.rpm',
    'libogg-1.0-5.i386.rpm',
    'libpng-1.2.2-17.i386.rpm',
    'libstdc++-3.3.2-1.i386.rpm',
    'libtiff-3.5.7-14.i386.rpm',
    'libuser-0.51.7-2.i386.rpm',
    'libvorbis-1.0-8.i386.rpm',
    'libxml-1.8.17-9.i386.rpm',
    'libxml2-2.5.11-1.i386.rpm',
    'libxslt-1.0.33-2.i386.rpm',
    'logrotate-3.6.10-1.i386.rpm',
    'losetup-2.11y-29.i386.rpm',
    'm4-1.4.1-14.i386.rpm',
    'mailcap-2.1.14-1.1.noarch.rpm',
    'mailx-8.1.1-31.1.i386.rpm',
    'make-3.79.1-18.i386.rpm',
    'man-1.5k-12.i386.rpm',
    'man-pages-1.60-4.noarch.rpm',
    'mktemp-1.5.1-1.i386.rpm',
    'mount-2.11y-29.i386.rpm',
    'mpage-2.5.3-6.i386.rpm',
    'ncurses-5.3-9.i386.rpm',
    'netpbm-9.24-12.i386.rpm',
    'newt-0.51.6-1.i386.rpm',
    'ntsysv-1.3.9-1.i386.rpm',
    'openldap-2.1.22-8.i386.rpm',
    'openssh-3.6.1p2-19.i386.rpm',
    'openssh-clients-3.6.1p2-19.i386.rpm',
    'openssh-server-3.6.1p2-19.i386.rpm',
    'openssl-0.9.7a-23.i386.rpm',
    'pam-0.77-15.i386.rpm',
    'passwd-0.68-4.i386.rpm',
    'patch-2.5.4-18.i386.rpm',
    'pcre-4.4-1.i386.rpm',
    'perl-5.8.1-92.i386.rpm',
    'perl-Filter-1.29-8.i386.rpm',
    'krb5-libs-1.3.1-6.i386.rpm',
    'libattr-2.4.1-2.i386.rpm',
    'hesiod-3.0.2-27.i386.rpm',
    'pnm2ppa-1.04-8.i386.rpm',
    'popt-1.8.1-0.30.i386.rpm',
    'portmap-4.0-57.i386.rpm',
    'procmail-3.22-11.i386.rpm',
    'procps-2.0.17-1.i386.rpm',
    'psmisc-21.3-2.RHEL.0.i386.rpm',
    'psutils-1.17-20.i386.rpm',
    'python-2.2.3-7.i386.rpm',
    'readline-4.3-7.i386.rpm',
    'fedora-release-1-3.i386.rpm',
    'rootfiles-7.2-6.noarch.rpm',
    'rpm-4.2.1-0.30.i386.rpm',
    'sed-4.0.8-1.i386.rpm',
    'sendmail-8.12.10-1.1.1.i386.rpm',
    'setup-2.5.27-1.1.noarch.rpm',
    'sgml-common-0.6.3-14.noarch.rpm',
    'shadow-utils-4.0.3-12.i386.rpm',
    'slang-1.4.5-18.1.i386.rpm',
    'slocate-2.6-10.i386.rpm',
    'specspo-9.0.92-1.noarch.rpm',
    'sysklogd-1.4.1-13.i386.rpm',
    'tar-1.13.25-12.i386.rpm',
    'tcl-8.3.5-93.i386.rpm',
    'tcsh-6.12-5.i386.rpm',
    'time-1.7-22.i386.rpm',
    'tmpwatch-2.9.0-2.i386.rpm',
    'umb-scheme-3.2-30.i386.rpm',
    'unzip-5.50-35.i386.rpm',
    'usermode-1.69-1.i386.rpm',
    'utempter-0.5.3-2.i386.rpm',
    'util-linux-2.11y-29.i386.rpm',
    'vim-common-6.2.121-1.i386.rpm',
    'vim-minimal-6.2.121-1.i386.rpm',
    'vixie-cron-3.0.1-76.i386.rpm',
    'which-2.16-1.i386.rpm',
    'words-2-21.noarch.rpm',
    'xinetd-2.3.12-4.10.0.i386.rpm',
    'zip-2.3-18.i386.rpm',
    'zlib-1.2.0.7-2.i386.rpm',
    'mingetty-1.06-2.i386.rpm',
    'iproute-2.4.7-11.i386.rpm',
    'modutils-2.4.25-13.i386.rpm',
    'gmp-4.1.2-9.i386.rpm',
    'expat-1.95.5-3.i386.rpm',
    'net-tools-1.60-20.1.i386.rpm',
    'nscd-2.3.2-101.i386.rpm',
    ],
    'ADDL' : [
    'apr-0.9.4-2.i386.rpm',
    'cyrus-sasl-devel-2.1.15-6.i386.rpm',
    'httpd-2.0.47-10.i386.rpm',
    'apr-devel-0.9.4-2.i386.rpm',
    'db4-devel-4.1.25-14.i386.rpm',
    'httpd-devel-2.0.47-10.i386.rpm',
    'apr-util-0.9.4-2.i386.rpm',
    'expat-devel-1.95.5-3.i386.rpm',
    'libtool-1.5-8.i386.rpm',
    'apr-util-devel-0.9.4-2.i386.rpm',
    'gcc-3.3.2-1.i386.rpm',
    'libtool-libs-1.5-8.i386.rpm',
    'autoconf-2.57-3.noarch.rpm',
    'gdbm-devel-1.8.0-21.i386.rpm',
    'openldap-devel-2.1.22-8.i386.rpm',
    'automake-1.7.8-1.noarch.rpm',
    'glibc-devel-2.3.2-101.i386.rpm',
    'python-devel-2.2.3-7.i386.rpm',
    'binutils-2.14.90.0.6-3.i386.rpm',
    'glibc-headers-2.3.2-101.i386.rpm',
    'cpp-3.3.2-1.i386.rpm',
    'glibc-kernheaders-2.4-8.36.i386.rpm',
    'finger-0.17-18.1.i386.rpm',
    'telnet-0.17-26.2.i386.rpm',
    'bind-utils-9.2.2.P3-9.i386.rpm',
    'vim-enhanced-6.2.121-1.i386.rpm',
    'wget-1.8.2-15.3.i386.rpm',
    'curl-7.10.6-7.i386.rpm',
    'mod_ssl-2.0.47-10.i386.rpm',
    'imap-2002d-3.i386.rpm',
    'telnet-server-0.17-26.2.i386.rpm',
    'vsftpd-1.2.0-5.i386.rpm',
    'rpm-build-4.2.1-0.30.i386.rpm',
    'nano-1.2.1-3.i386.rpm',
    'cvs-1.11.5-3.i386.rpm',
    'libstdc++-devel-3.3.2-1.i386.rpm',
    'gcc-c++-3.3.2-1.i386.rpm',
    'http://download.fedora.us/fedora/fedora/1/i386/RPMS.stable/apt-0.5.15cnc5-0.fdr.10.1.i386.rpm'
    ] }
  
SSL_CONFIG = """
HOME= .
RANDFILE = $ENV::HOME/.rnd

[ req ]
default_bits = 1024
encrypt_key = yes
distinguished_name = req_dn
x509_extensions = cert_type

[ req_dn ]
countryName = Country Name (2 letter code)
countryName_default             = NO
countryName_min                 = 2
countryName_max                 = 2
countryName_value               = US

stateOrProvinceName             = State or Province Name (full name)
stateOrProvinceName_default     = Some-State
stateOrProvinceName_value       = Virginia

localityName                    = Locality Name (eg, city)
localityName_value              = Vienna

0.organizationName              = Organization Name (eg, company)
0.organizationName_default      = FooBar Inc.
0.organizationName_value        = OpenHosting, Inc.

organizationalUnitName          = Organizational Unit Name (eg, section)
organizationalUnitName_value    = Security Department

0.commonName                    = Common Name (FQDN of your server)
0.commonName_value              = www.openhosting.com

1.commonName                    = Common Name (default)
1.commonName_value              = localhost

[ cert_type ]
nsCertType = server
"""

HTTPD_CONF = """
<IfModule mod_proxy.c>
  # OpenHosting panel proxy
  ProxyRequests           Off
  ProxyPass               /ohadmin/ http://127.0.0.1:1011/
  ProxyPassReverse        /ohadmin/ http://127.0.0.1:1011/
</IfModule>
"""

RNDSLEEP = """\
#!/bin/bash

# (c) 2004 OpenHosting, Inc.

sleep $(($RANDOM %  ${1:-1}))

"""

CRONTAB = """\
SHELL=/bin/bash
PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/bin
MAILTO=root
HOME=/

#
# NOTE the rndsleep command will sleep a random number of seconds for
# up to the argument given. It is there to prevent virtual servers from
# doing heavy disk IO all at the same time.
#
# BE COURTEOUS, LEAVE IT THERE.
#
01 * * * * root rndsleep 60 && run-parts /etc/cron.hourly
02 4 * * * root rndsleep 1200 && run-parts /etc/cron.daily
22 4 * * 0 root rndsleep 1200 && run-parts /etc/cron.weekly
42 4 1 * * root rndsleep 1200 && run-parts /etc/cron.monthly
"""
