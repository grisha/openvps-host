/*
 *
 * Copyright 2004 OpenHosting, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * $Id: common.c,v 1.3 2004/10/15 21:35:38 grisha Exp $
 * 
 */

#include <stdio.h>
#include <unistd.h>

#include "common.h"

int run(char *command, int argc, char *argv[]) {

    char **tmp, **tmp2;
    int i;

    char *ssh_argv[] = {
        "/usr/bin/ssh",
        "-q",
        "-t", 
        "-i", AUTH_KEY,
        "-o", "PreferredAuthentications=publickey",
        "-o", "NumberOfPasswordPrompts=0",
        "-o", "NoHostAuthenticationForLocalhost=yes",
        "-c", "blowfish", 
	//        "-v", 
        "-p", SSH_PORT,
        SSH_USER "@" SSH_HOST, 
        command
    };
    int SSH_ARGC = sizeof(ssh_argv)/sizeof(ssh_argv[0]);

    /* no 1 for the null because we will be dropping 1
       arg - the name of _this_ command */
    tmp = (char**)malloc((argc+SSH_ARGC)*sizeof(char**));
    tmp2 = tmp;

    /* copy arguments for the ssh part of the command */

    for (i=0; i<SSH_ARGC; i++)
        *tmp++ = (char*)strdup(ssh_argv[i]);

    /* copy the rest of them, skip the command name */

    for (i=1; i<argc; i++)
        *tmp++ = (char*)strdup(argv[i]);

    *tmp = '\0';

    /* run it as root */
    setuid(0);
    return execv(tmp2[0], tmp2);
    
}
