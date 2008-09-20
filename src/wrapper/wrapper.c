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
 * $Id: wrapper.c,v 1.8 2008/09/20 17:09:13 grisha Exp $
 *
 */

#include <stdio.h>
#include <stdarg.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <grp.h>
#include "wrapper.h"

const char *VALID_COMMANDS[] = {
    "vserver-start",
    "vserver-stop",
    "vserver-stat",
    "read-config",
    "openvps-rebuild",
    "openvps-bwlimit",
    "openvps-fw",
    "openvps-suspend",
    "openvps-unsuspend",
    "openvps-checkpw",
    NULL 
};

char *ENV[] = {
    NULL
};

#define BUFSIZE 1024

void log_error(char *format, ...) {

    char log_entry[BUFSIZE];

    va_list arg_ptr;
    va_start(arg_ptr, format);

    vsnprintf(log_entry, BUFSIZE, format, arg_ptr);
    va_end(arg_ptr);

    openlog("OpenVPS-wrapper", LOG_CONS, LOG_DAEMON);
    syslog(LOG_ERR, "%s\n", log_entry);
    closelog();

}

int check_command(char *command) {

    int i = 0;

    while (VALID_COMMANDS[i] != NULL) {
        if (!strcmp(command, VALID_COMMANDS[i]))
            return 1;
        i++;
    }
    return 0;

}

int check_group() {
    
    /* make sure we're called from apache's group for a bit of
       added security */

    gid_t mygid = getgid();
    struct group *mygroup = getgrgid(mygid);

    if (!mygroup) {
        log_error("Error: called with non-existent group: %d\n", mygid);
        return 0;
    }
        
    if (strcmp(APACHE_GROUP, mygroup->gr_name)) {
        log_error("Error: called with group \"%s\", expected group \"%s\".\n", 
                  mygroup->gr_name, APACHE_GROUP);
        return 0;
    }
    return 1;
}     

int run_command(const char* command, int argc, char** argv) {

    int status;

    status = setreuid(geteuid(), -1);
    if (status) {
        log_error("Error: %s", strerror(errno));
        exit(1);
    }

    if (!strcmp(command, "vserver-start")) {

        char *newargv[] = {
            VSERVER,
            NULL,
            "start",
            NULL 
        };

        if (argc >= 3) 
            /* this is vserver name */
            newargv[1] = argv[2];

        /* run it with empty environment */
        execve(VSERVER, newargv, ENV);

    }
    else if (!strcmp(command, "vserver-stop")) {

        char *newargv[] = {
            VSERVER,
            NULL,
            "stop",
            NULL 
        };

        if (argc >= 3) 
            /* this is vserver name */
            newargv[1] = argv[2];

        /* run it with empty environment */
        execve(VSERVER, newargv, ENV);

    }
    else if (!strcmp(command, "vserver-stat")) {

        char *newargv[] = {
            VSERVER "-stat",
            NULL,
        };

        /* run it with empty environment */
        execve(VSERVER "-stat", newargv, ENV);
    }
    else if (!strcmp(command, "read-config")) {

        char *newargv[] = {
            "/bin/cat",
            CONFIG_FILE,
            NULL,
        };

        /* run it with empty environment */
        execve("/bin/cat", newargv, ENV);
    }
    else if (!strcmp(command, "openvps-rebuild")) {

        char *newargv[] = {
            OPENVPS,
            "rebuild",
            NULL,
            NULL,
            NULL
        };

        if (argc >= 4) {
            newargv[2] = argv[2]; /* refroot */
            newargv[3] = argv[3]; /* vps name */
        }

        /* run it with empty environment */
        execve(OPENVPS, newargv, ENV);
        
    }
    else if (!strcmp(command, "openvps-bwlimit")) {

        char *newargv[] = {
            OPENVPS,
            "bwlimit",
            NULL,
            NULL,
            NULL
        };

        if (argc >= 4) {
            newargv[2] = argv[2]; /* vps name */
            newargv[3] = argv[3]; /* bwlimit */
        }

        /* run it with empty environment */
        execve(OPENVPS, newargv, ENV);

    }
    else if (!strcmp(command, "openvps-fw")) {

        int i = 0;
        char *newargv[1024];

        newargv[0] = OPENVPS;
        newargv[1] = "fw";

        if (argc >= 4) {
            newargv[2] = argv[2];
            newargv[3] = argv[3];

            for (i=4; (i < argc) && (i < 1024); i++) {
                newargv[i] = argv[i];
            }
            newargv[i] = NULL;

            /* run it with empty environment */
            execve(OPENVPS, newargv, ENV);
        }
    }
    else if (!strcmp(command, "openvps-suspend")) {

        char *newargv[] = {
            OPENVPS,
            "suspend",
            NULL,
            NULL 
        };

        if (argc >= 3) 
            /* this is vserver name */
            newargv[2] = argv[2];

        /* run it with empty environment */
        execve(OPENVPS, newargv, ENV);
    }
    else if (!strcmp(command, "openvps-unsuspend")) {

        char *newargv[] = {
            OPENVPS,
            "unsuspend",
            NULL,
            NULL 
        };

        if (argc >= 3) 
            /* this is vserver name */
            newargv[2] = argv[2];

        /* run it with empty environment */
        execve(OPENVPS, newargv, ENV);
    }
    else if (!strcmp(command, "openvps-checkpw")) {
        
        char *newargv[] = {
            OPENVPS,
            "checkpw",
            NULL,
            NULL,
            NULL 
        };

        if (argc >= 4) {
            /* this is vserver name */
            newargv[2] = argv[2];
            /* userid */
            newargv[3] = argv[3];
        }

        /* run it with empty environment */
        execve(OPENVPS, newargv, ENV);
        
    }

    /* we failed if we got this far */
    log_error("Error: %s", strerror(errno));
    return 1;
}


int main(int argc, char** argv) {
    
    int status;

    if (argc < 2) {
        log_error("Usage: %s program [args...]", argv[0]);
        exit(1);
    }

    if (!check_command(argv[1])) {
        log_error("Illegal command: %s", argv[1]);
        exit(1);
    }

    if (!check_group()) {
        /* check_group does its own logging */
        exit(1);
    }

    status = run_command(argv[1], argc, argv);
    return status;
}
