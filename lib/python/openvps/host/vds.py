#
# Copyright 2008 OpenHosting, Inc.
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

# $Id: vds.py,v 1.27 2008/09/20 17:09:13 grisha Exp $

""" VDS related functions """

import os
import sys
import stat
import shutil
import commands
import tempfile
import time
import urllib
import types
import hmac

# python-rpm
import rpm

# openvps modules
import cfg
import vsutil
from openvps.common import util
from openvps.host.distro import distro_util

DRYRUN = 0


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
            result.append(os.path.join(distroot, pkgdict[pkg]))

    return result
                

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

def buildref(refroot, distroot, bundles=None):

    print "Probing distribution at %s..." % distroot
    dist = distro_util.probe_distro(refroot, distroot)

    if not dist:
        print "ERROR: Distribution at %s is unknown to us" % distroot
        print "Exiting."
        return

    print "Detected %s" % dist.get_desc()
    print 'Building a reference server at %s using packages in %s' % \
          (refroot, distroot)

    dist.buildref(bundles)

def vserver_vroot_perms():

    # set perms on VSERVERS_ROOT
    # ...better safe than sorry...

    print 'Doing chmod 0000 %s, just in case' % cfg.VSERVERS_ROOT

    os.chmod(cfg.VSERVERS_ROOT, 0)


def customize(name, xid, ip, userid, passwd, disklim, dns=cfg.PRIMARY_IP,
              vpn_ip=None, vpn_mask='255.255.255.0'):

    vpsroot = os.path.join(cfg.VSERVERS_ROOT, name)

    print "Probing VPS version at %s..." % vpsroot
    vps = distro_util.probe_vps(vpsroot)

    if not vps:
        print "ERROR: VPS version at %s is unknown to us" % vpsroot
        print "Exiting."
        return

    print "Detected %s" % vps.get_desc()

    vps.customize(name, xid, ip, userid, passwd, disklim, dns,
                  vpn_ip, vpn_mask)

    vps.fixxids(xid)

    vserver_vroot_perms()

def custcopy(name, srcpath):

    print "Probing VPS version at %s..." % srcpath
    src = distro_util.probe_vps(srcpath)
    
    if not src:
        print "ERROR: VPS version at %s is unknown to us" % srcpath
        print "Exiting."
        return
    print "Detected %s" % src.get_desc()

    if src.cancopy() != []:
        print "ERROR: the source VPS does not have: %s" % `src.cancopy()`
        return

    vpsroot = os.path.join(cfg.VSERVERS_ROOT, name)
    print "Probing VPS version at %s..." % vpsroot
    vps = distro_util.probe_vps(vpsroot)

    if not vps:
        print "ERROR: VPS version at %s is unknown to us" % vpsroot
        print "Exiting."
        return
    print "Detected %s" % vps.get_desc()

    xid = vps.custcopy(src, name, name)
    vps.fixxids(xid)

def rebuild(refroot, name):

    # make sure it is stopped
    if vsutil.is_running(name):
        print "ERROR: %s is running, you must first stop it" % name
        return
    
    vpspath = os.path.join(cfg.VSERVERS_ROOT, name)

    # create a rebuild lock
    lock = os.path.join(cfg.ETC_VSERVERS, name, '.rebuild')
    if os.path.exists(lock):
        print "ERROR: %s exists - is it being rebuilt?" % lock
        print "Cannot rebuild, aborting..."
        return
    
    # create the lock
    open(lock, 'w')

    try:

        print "Probing VPS version at %s..." % vpspath
        vps = distro_util.probe_vps(vpspath)
        if not vps:
            print "ERROR: VPS version at %s is unknown to us" % vpspath
            print "Exiting."
            return
        print "Detected %s" % vps.get_desc()

        if vps.cancopy() != []:
            print "ERROR: the source VPS does not have: %s" % `vps.cancopy()`
            print "Cannot rebuild, aborting..."
            return

        # need to make sure reference server is good too
        print "Probing VPS version at %s..." % refroot
        ref = distro_util.probe_vps(refroot)
        if not ref:
            print "ERROR: VPS version at %s is unknown to us" % refroot
            print "Exiting."
            return
        print "Detected %s" % vps.get_desc()
        
        # rename it to something temporary. there is a bit of a race
        # condition here.

        d = tempfile.mkdtemp(prefix='.rebuild', dir=cfg.VSERVERS_ROOT)
        os.rmdir(d)
        temppath = d

        print 'Renaming %s -> %s...' % (vpspath, temppath)
        os.rename(vpspath, temppath)

        # touch it, so that it does not get wiped by the
        # ovcleanrebuilds cron script
        os.utime(temppath, None)

        # clone it
        clone(refroot, vpspath)

        #custcopy it
        custcopy(name, temppath)

        print 'remember to delete %s' % temppath

    finally:
        os.remove(lock)

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

def copytime(src, dst):
    # XXX unused?
    """Copy timestamps (don't bother with symlinks,
       those cannot be changed in unix) """
    st = os.stat(src)
    os.utime(dst, (st.st_atime, st.st_mtime))

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
            copytime(src, dst)
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

    print "Probing VPS version at %s..." % source
    vps = distro_util.probe_vps(source)

    if not vps:
        print "ERROR: VPS version at %s is unknown to us" % source
        print "Exiting."
        return

    print "Detected %s" % vps.get_desc()

    vps.clone(dest, pace)


bytes, lins = 0, 0

def unify(source, dest, pace=cfg.PACE[0]):

    global bytes, lins

    # pace counter
    p = 0

    # this will also strip trailing slashes
    source, dest = os.path.abspath(source), os.path.abspath(dest)

    print 'Unifying %s -> %s ... (this will take a while)' % (source, dest)

    # this will prevent some warnings
    os.chdir(cfg.VSERVERS_ROOT)
    
    #print source, dest

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

            if not os.path.exists(dst) or not os.path.isfile(src) or os.path.islink(src):
                # nothing to do here
                continue

#            print reldst, src, dst

            c, t, s = match_path(reldst)

            # copy/touch/skip?
            if not (c or t or s):

                # config?
                if not is_config(source, reldst):

                    # do they look the same?

                    src_stat = os.lstat(src)
                    dst_stat = os.lstat(dst)

                    if src_stat.st_dev == dst_stat.st_dev and \
                       src_stat.st_ino != dst_stat.st_ino and \
                       src_stat.st_uid == dst_stat.st_uid and \
                       src_stat.st_gid == dst_stat.st_gid and \
                       src_stat.st_size == dst_stat.st_size and \
                       src_stat.st_mtime == dst_stat.st_mtime:

                        # XXX add MD5 (of at least beginning) check here?
                    
                        # flags ok?
                        if vsutil.is_file_immutable_unlink(src):

                            # go for it
                            vsutil.unify(src, dst)
                            bytes += src_stat.st_size
                            lins += 1
                        else:
                            print 'Warning: not unifying %s because it is not iunlink' % src

    print 'Done.'

    print 'Files unified:'.ljust(20), lins
    print 'Bytes saved:'.ljust(20), bytes


def dump(vserver_name, refserver, outfile, pace=cfg.PACE[0]):

    # Save the difference between reference and the server in an
    # archive The archive is encrypted. This is because you have to
    # trust it before you try restoring it. It is also better for any
    # backed up data to be encrypted always.

    # pace counter
    p = 0

    # this will also strip trailing slashes
    vserver, refserver = os.path.abspath(os.path.join(cfg.VSERVERS_ROOT, vserver_name)), \
                         os.path.abspath(refserver)

    print 'Dumping %s in reference to %s ... (this will take a while)' % (vserver, refserver)

    # this will prevent some warnings
    os.chdir(cfg.VSERVERS_ROOT)

    # first we need a header. for now the header format is:
    # "openvps-dump|Fedora Core release 2 (Tettnang)|2004010101|userid|ctxid|ip|hmac"
    # where the fields are:
    # * \0openvps-dump (constant) (the \0 makes it apear like a binary file to less)
    # * /etc/fedora-release from reference server
    # * /etc/openvps-release from reference (default to YYYYMMDDHHMMSS
    # * name of vserver
    # * context id of vserver
    # * ips in format dev:ip/mask,dev:ip/mask
    # * current disk limits (the argument to -S of vdlim)
    # * hmac of the preceeding string

    config = vsutil.get_vserver_config(vserver_name)

    header = ['\0openvps-dump']
    header.append(open(os.path.join(refserver, 'etc/fedora-release')).read().strip())
    if os.path.exists(os.path.join(refserver, 'etc/openvps-release')):
        header.append(open(os.path.join(refserver, 'etc/openvps-release')).read().strip())
    else:
        header.append(time.strftime('%Y%m%d%H%M%S', time.localtime()))
    header.append(vserver_name)
    header.append(config['context'])
    header.append(','.join(['%s:%s/%s' % (i['dev'], i['ip'], i['mask']) for i in config['interfaces']]))

    dl = vsutil.get_disk_limits(config['context'])
    if dl:
        header.append('%s,%s,%s,%s,%s' % (dl['b_used'], dl['b_total'], dl['i_used'], dl['i_total'], dl['root']))
    else:
        print 'Wargning: no disk limits for xid %s' % config['context']
        header.append('None')

    # turn it into string
    header = '|'.join(header)

    # sign it
    digest = hmac.new(cfg.DUMP_SECRET, header).hexdigest()

    # now write to our file
    open(outfile, 'w').write('%s|%s|\0' % (header, digest))
    
    # open a pipe to cpio
    fd_r, fd_w = os.pipe()

    # write the password to the new file descriptor so openssl can read it
    os.write(fd_w, cfg.DUMP_SECRET+'\n')

    # cpio will be fed the list of files to archive. the output is compressed using
    # bzip2, then encrypted with openssl using blowfish
    cmd = '/bin/cpio -oHcrc | /usr/bin/bzip2 | /usr/bin/openssl bf -salt -pass fd:%d >> %s' % (fd_r, outfile)
    pipe = os.popen(cmd, 'w', 0)

    # the first things to go into the archive should be the config and rrd
    
    # config
    cfg_dir = os.path.join(cfg.ETC_VSERVERS, vserver_name)
    cmd = '/usr/bin/find %s -print' % cfg_dir
    cfg_files = commands.getoutput(cmd)
    pipe.write(cfg_files+'\n')

    # the rrd
    rrd_path = os.path.join(cfg.VAR_DB_OPENVPS, vserver_name+'.rrd')
    pipe.write(rrd_path+'\n')
    
    #print source, dest
    for root, dirs, files in os.walk(vserver, topdown=False):

        for file in files + dirs:

            if pace and p >= pace:
                sys.stdout.write('.'); sys.stdout.flush()
                time.sleep(cfg.PACE[1])
                p = 0
            else:
                p += 1

            src = os.path.join(root, file)

            # reldst is they way it would look inside vserver
            reldst = os.path.join(max(root[len(vserver):], '/'), file)
            dst = os.path.join(refserver, reldst[1:])

            if os.path.exists(dst):

                if os.path.islink(dst) or os.path.isdir(dst) or not os.path.isfile(dst):
                    
                    # If this is a link, dir or other non-file, their
                    # mere existence is sufficient, no need to compare
                    # inodes since these are never unified. But we
                    # need to make sure they are not skipped (copy
                    # means they will be there after cloning, touch
                    # doesn't apply here)
                    
                    c, t, s = match_path(file)

                    if not s:
                        continue
                else:

                    # this is a regular file that exists in both
                    # reference and our server, let's compare inodes

                    src_stat = os.lstat(src)
                    dst_stat = os.lstat(dst)

                    if src_stat.st_ino == dst_stat.st_ino:
                        
                        # inodes match, this is a unified file, no
                        # reason to back it up

                        continue
            pipe.write(src+'\n')

    os.close(fd_w)
    pipe.close()

def restore(dumpfile, refserver):

    # this is quite simply the reverse of dump

    # first let's check the sig

    # XXX is 4096 enough?
    header = open(dumpfile).read(4096)

    if header[:len('\openvps-dump')] != '\0openvps-dump':
        print '%s is not an openvps-dump file, aborting.' % dumpfile
        return

    # this would need to be adjusted if we alter the header
    h_len = 8 # including the sig

    header, junk = header.split('|\0', 1)

    # remember the offset
    offset = len(header)+2

    header = header.split('|', h_len)
    if len(header) < h_len:
        print 'Bad header, %s may be corrupt, aborting.' % dumpfile
        return

    header, stored_digest = '|'.join(header[:-1]), header[-1]
    digest = hmac.new(cfg.DUMP_SECRET, header).hexdigest()
    if stored_digest != digest:
        print 'The header signature in %s is bad, check your DUMP_SECRET value, aborting.' % dumpfile
        return

    # split it back now
    header = header.split('|')

    ## now do some sanity checking: make sure xid, name and ips aren't in use
    abort = 0
    
    vss = vsutil.list_vservers()

    # check name
    vserver_name = header[3]
    if vss.has_key(vserver_name):
        print 'New vserver "%s" already exists.' % vserver_name
        abort = 1

    # check xid
    context = header[4]
    for vs in vss.keys():
        if vss[vs]['context'] == context:
            print 'New vserver "%s" wants xid %s, but it is in use by "%s".' \
                  % (vserver_name, context, vs)
            abort = 1

    # check ips
    ips = header[5].split(',')
    ips = [ip.split(':')[1].split('/')[0] for ip in ips]
    for vs in vss.keys():
        for ifc in vss[vs]['interfaces']:
            if ifc['ip'] in ips:
                print 'New vserver "%s" wants ip %s, but it is in use by "%s".' \
                      % (vserver_name, ifc['ip'], vs)
                abort = 1

    # does the target exist?
    path = os.path.join(cfg.VSERVERS_ROOT, vserver_name)
    if os.path.exists(path):
        print 'Path %s already exists, please fix this first.' % path
        abort = 1

    path = os.path.join(cfg.VSERVERS_ROOT, context)
    if os.path.exists(path):
        print 'Path %s already exists, please fix this first.' % path
        abort = 1

    if abort:
        print 'Aborting.'
        return

    ## at this point it should be safe to restore

    ## first clone it
    clone(refserver,  os.path.join(cfg.VSERVERS_ROOT, vserver_name))

    ## now unarchive
    fd_r, fd_w = os.pipe()

    # write the password to the new file descriptor so openssl can read it
    os.write(fd_w, cfg.DUMP_SECRET+'\n')

    # note that we specify 'u' in cpio here for unconditionl,
    # i.e. don't worry about overwriting newer files with older
    # ones. this is the only way it would work if the reference server
    # has progressed and has a newer rpm database. a subsequent
    # vserver update should cure any incompatibilities anyway.

    cmd = 'dd if=%s bs=1 skip=%d obs=1024 | /usr/bin/openssl bf -d -salt -pass fd:%d | /usr/bin/bzip2 -d | /bin/cpio -idvuHcrc' \
          % (dumpfile, offset, fd_r)
    pipe = os.popen(cmd, 'r', 0)
    s = pipe.read(1)
    while s:
        sys.stdout.write(s); sys.stdout.flush()
        s = pipe.read(1)
    pipe.close()
    os.close(fd_w)

    ## lastly fix xids
    fixxids(os.path.join(cfg.VSERVERS_ROOT, vserver_name), context)

    ## and finally, set the disk limits
    dl = header[6]
    d_used, d_lim, i_used, i_lim, r = dl.split(',')
    vserver_disk_limit(os.path.join(cfg.VSERVERS_ROOT, vserver_name),
                       context, d_lim, d_used=d_used, i_used=i_used)

    print 'Done!'

def fixflags(refroot):

    print "Probing VPS version at %s..." % refroot
    vps = distro_util.probe_vps(refroot)

    if not vps:
        print "ERROR: VPS version at %s is unknown to us" % refroot
        print "Exiting."
        return

    print "Detected %s" % vps.get_desc()

    vps.fixflags()

def fixxids(vpsroot, xid, pace=cfg.PACE[0]):

    print "Probing VPS version at %s..." % vpsroot
    vps = distro_util.probe_vps(vpsroot)

    if not vps:
        print "ERROR: VPS version at %s is unknown to us" % vpsroot
        print "Exiting."
        return

    print "Detected %s" % vps.get_desc()

    vps.fixxids(xid)

def delete(vserver):

    # is it running?

    lines = commands.getoutput('vserver-stat').splitlines()
    for line in lines:
        if line.split()[7] == vserver:
            print 'Vserver "%s" appears to be running, stop it first.' % vserver
            return

    config = vsutil.get_vserver_config(vserver)

    vserver_path = os.path.join(cfg.VSERVERS_ROOT, vserver)
    print 'Deleting %s....' % vserver_path

    cmd = 'chattr -iR %s' % os.path.join(vserver_path, 'lib/modules')
    print cmd
    commands.getoutput(cmd)
    
    cmd = 'rm -rf %s' % vserver_path
    print cmd
    commands.getoutput(cmd)

    context_path = os.path.join(cfg.VSERVERS_ROOT, config['context'])

    if os.path.exists(context_path):
    
        cmd = 'rm -rf %s' % context_path
        print cmd
        commands.getoutput(cmd)

    config_path = os.path.join(cfg.ETC_VSERVERS, vserver)
    cmd = 'rm -rf %s' % config_path
    print cmd
    commands.getoutput(cmd)

    rrd_path = os.path.join(cfg.VAR_DB_OPENVPS, vserver+'.rrd')
    cmd = 'rm %s' % rrd_path
    print cmd
    commands.getoutput(cmd)

    # remove disk limits
    cmd = '%s --xid %s --remove %s' % (cfg.VDLIMIT, config['context'], cfg.VSERVERS_ROOT)
    print cmd
    s = commands.getoutput(cmd)
    print s

    if 'invalid option' in s:
        # old vdlimit (XXX this can go away soon)
        print ' WARNING! OLD VDLIMIT! Upgrade your util-vserver to 0.30.207+. Using old vdlimit:'
        cmd = '%s -d -x %s %s' % (cfg.VDLIMIT, config['context'], cfg.VSERVERS_ROOT)
        print ' ', cmd
        print commands.getoutput(cmd)
    
    # remove iptables? It's probably best not to remove iptables
    # counters, since all that's going to do is disrupt the counter
    # should you restore the vserver back.
    # XXX is this true?

def addip(vserver, ip, dev, mask):

    # add a second ip address to a vserver
    
    vsutil.add_vserver_ip(vserver, ip, dev, mask)

def set_bwlimit(vserver, limit):

    vss = vsutil.list_vservers()
    if not vss.has_key(vserver):
        print 'ERROR: No such vserver: %s' % vserver
        return

    vsutil.set_bwlimit(vserver, limit)
    vsutil.set_tc_class(vserver)

def rpm_which_package(ts, root, file):

    # just like rpm -qf file

    it = ts.dbMatch('basenames', file)

    try:
        hdr = it.next()
    except StopIteration:
        return None

    #return hdr[rpm.RPMTAG_NAME]
    return hdr

def rpm_list_files(hdr):

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

rpm_cache = {}

def rpm_file_isconfig(root, file):

    global rpm_cache

    ts = rpm.TransactionSet(root)

    if not rpm_cache.has_key(file):
        
        hdr = rpm_which_package(ts, root, file)
        if not hdr:
            # assume it's config if not found, this will
            # make sure it is copied, not linked
            rpm_cache[file] = {'isconfig':1}
        else:
            rpm_cache.update(rpm_list_files(hdr))

            # it's possible that which_package thinks a package is of an rpm
            # but then it's not actually there
            if file not in rpm_cache:
                rpm_cache[file] = {'isconfig':1}

    ts = None

    return rpm_cache[file]['isconfig']

def is_config(root, file):
    return rpm_file_isconfig(root, file)


def suspend(vserver):

    if os.getuid() == 0:

        # mark it as suspended
        suspend_dir = os.path.join(cfg.VAR_DB_OPENVPS, 'suspend')
        if not os.path.exists(suspend_dir):
            os.mkdir(suspend_dir)

        suspend_path = os.path.join(cfg.VAR_DB_OPENVPS, 'suspend', vserver)
        if not os.path.exists(suspend_path):
            open(suspend_path, 'w')

        # suspend and stop vps
        vsutil.suspend(vserver)

    else:
        # run through wrapper
        return commands.getoutput('%s openvps-suspend %s' % (cfg.OVWRAPPER, vserver))
        

def unsuspend(vserver):

    if os.getuid() == 0:

        # remove suspend mark
        suspend_path = os.path.join(cfg.VAR_DB_OPENVPS, 'suspend', vserver)
        if os.path.exists(suspend_path):
            os.unlink(suspend_path)

        # unsuspend and start
        vsutil.unsuspend(vserver)
        
    else:
        # close descriptors, run via wrapper, see vsutil.start()

        pid = os.fork()
        if pid == 0:
            
            # in child

            # now close all file descriptors
            for fd in range(os.sysconf("SC_OPEN_MAX")):
                try:
                    os.close(fd)
                except OSError:   # ERROR (ignore)
                    pass

            # only now is it OK to do our thing
            os.system('%s openvps-unsuspend %s > /dev/null 2>&1 &' % (cfg.OVWRAPPER, vserver))

            # exit child
            os._exit(0)
            
        else:
            # wait on the child to avoid a defunct (zombie) process
            os.wait()


def fw_start(vserver, mode):

    vss = vsutil.list_vservers()
    if not vss.has_key(vserver):
        print 'ERROR: No such vserver: %s' % vserver
        return

    vsutil.fw_start(vserver, mode)

def fw_open(vserver, proto, port, ips=[]):

    vss = vsutil.list_vservers()
    if not vss.has_key(vserver):
        print 'ERROR: No such vserver: %s' % vserver
        return

    vsutil.fw_open(vserver, proto, port, ips)

def fw_close(vserver, proto, port, ips=[]):

    vss = vsutil.list_vservers()
    if not vss.has_key(vserver):
        print 'ERROR: No such vserver: %s' % vserver
        return

    vsutil.fw_close(vserver, proto, port, ips)

def fw_finish(vserver):

    vss = vsutil.list_vservers()
    if not vss.has_key(vserver):
        print 'ERROR: No such vserver: %s' % vserver
        return

    vsutil.fw_finish(vserver)

    # this is a bit of a hack - it seems that upon startup not
    # necessary modules are loaded confusing our vserver startup
    # when we save them, the OS will figure out what needs to be
    # loaded.
    cmd = "/sbin/service iptables save"
    print cmd
    print commands.getoutput(cmd)

def fw_clear_block(vserver):

    vss = vsutil.list_vservers()
    if not vss.has_key(vserver):
        print 'ERROR: No such vserver: %s' % vserver
        return

    vsutil.fw_clear_block(vserver)

def fw_block(vserver, ips):

    vss = vsutil.list_vservers()
    if not vss.has_key(vserver):
        print 'ERROR: No such vserver: %s' % vserver
        return

    vsutil.fw_block(vserver, ips)

    
def getpwhash(vserver, userid):
    # we assume they're using shadow here
    vpsroot = os.path.join(cfg.VSERVERS_ROOT, vserver)
    shlines = open(os.path.join(vpsroot, 'etc/shadow')).readlines()
    for line in shlines:
        userid_, pwhash, rest = line.split(':', 2)
        if userid == userid_:
            return pwhash

    return None

def checkpw(vserver, userid, passwd):

    if os.getuid() == 0:

        pwhash = getpwhash(vserver, userid)
        return util.check_passwd(passwd, pwhash)
        
    else:
        # close descriptors, run via wrapper, see vsutil.start()

        pid = os.fork()
        if pid == 0:
            
            # in child

            # now close all file descriptors
            for fd in range(os.sysconf("SC_OPEN_MAX")):
                try:
                    os.close(fd)
                except OSError:   # ERROR (ignore)
                    pass

            pipe = os.popen('%s openvps-checkpw %s %s' % (cfg.OVWRAPPER, vserver, userid), 'w')
            pipe.write(passwd)
            sts = pipe.close()

            if sts is None:
                os._exit(os.EX_OK)
            else:
                os._exit(os.EX_OSERR)

        else:
            # wait on the child to avoid a defunct (zombie) process
            pid, sts = os.wait()
            return sts == 0

