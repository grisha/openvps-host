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
 * $Id: ohchkpwd.c,v 1.1 2004/03/25 16:48:40 grisha Exp $
 * 
 * This file is based on unix_chkpwd.c by Andrew G. Morgan, the
 * Copyright for which is at the bottom of this file.
 *
 * This program expects userid:password from stdin and its exit
 * status of 0 indicates that the password is OK.
 *
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/types.h>
#include <pwd.h>
#include <shadow.h>
#include <signal.h>

#define MAXPASS		200	/* the maximum length of a password */

extern char *crypt(const char *key, const char *salt);
#define  x_strdup(s)  ( (s) ? strdup(s):NULL )

#define UNIX_PASSED	0
#define UNIX_FAILED	1

/* syslogging function for errors and other information */

static void _log_err(int err, const char *format,...)
{
	va_list args;

	va_start(args, format);
	openlog("ohchkpwd", LOG_CONS | LOG_PID, LOG_AUTH);
	vsyslog(err, format, args);
	va_end(args);
	closelog();
}

static void su_sighandler(int sig)
{
	if (sig > 0) {
		_log_err(LOG_NOTICE, "caught signal %d.", sig);
		exit(sig);
	}
}

static void setup_signals(void)
{
	struct sigaction action;	/* posix signal structure */

	/*
	 * Setup signal handlers
	 */
	(void) memset((void *) &action, 0, sizeof(action));
	action.sa_handler = su_sighandler;
	action.sa_flags = SA_RESETHAND;
	(void) sigaction(SIGILL, &action, NULL);
	(void) sigaction(SIGTRAP, &action, NULL);
	(void) sigaction(SIGBUS, &action, NULL);
	(void) sigaction(SIGSEGV, &action, NULL);
	action.sa_handler = SIG_IGN;
	action.sa_flags = 0;
	(void) sigaction(SIGTERM, &action, NULL);
	(void) sigaction(SIGHUP, &action, NULL);
	(void) sigaction(SIGINT, &action, NULL);
	(void) sigaction(SIGQUIT, &action, NULL);
}

static int _unix_verify_password(const char *name, const char *p, int opt)
{
	struct passwd *pwd = NULL;
	struct spwd *spwdent = NULL;
	char *salt = NULL;
	char *pp = NULL;
	int retval = UNIX_FAILED;
	int salt_len;

	/* UNIX passwords area */
	setpwent();
	pwd = getpwnam(name);	/* Get password file entry... */
	endpwent();
	if (pwd != NULL) {
		if (strcmp(pwd->pw_passwd, "x") == 0) {
			/*
			 * ...and shadow password file entry for this user,
			 * if shadowing is enabled
			 */
			setspent();
			spwdent = getspnam(name);
			endspent();
			if (spwdent != NULL)
				salt = x_strdup(spwdent->sp_pwdp);
			else
				pwd = NULL;
		} else {
			if (strcmp(pwd->pw_passwd, "*NP*") == 0) {	/* NIS+ */
				uid_t save_uid;

				save_uid = geteuid();
				seteuid(pwd->pw_uid);
				spwdent = getspnam(name);
				seteuid(save_uid);

				salt = x_strdup(spwdent->sp_pwdp);
			} else {
				salt = x_strdup(pwd->pw_passwd);
			}
		}
	}
	if (pwd == NULL || salt == NULL) {
		_log_err(LOG_ALERT, "check pass; user unknown");
		p = NULL;
		return retval;
	}

	salt_len = strlen(salt);
	if (salt_len == 0) {
		return (opt == 0) ? UNIX_FAILED : UNIX_PASSED;
	}

	/* the moment of truth -- do we agree with the password? */
	retval = UNIX_FAILED;

	if (*salt == '*') {
	    retval = UNIX_FAILED;
	} else {
		pp = crypt(p, salt);
		if (strncmp(pp, salt, salt_len) == 0) {
			retval = UNIX_PASSED;
		}
	}
	p = NULL;		/* no longer needed here */

	/* clean up */
	{
		char *tp = pp;
		if (pp != NULL) {
			while (tp && *tp)
				*tp++ = '\0';
			free(pp);
		}
		pp = tp = NULL;
	}

	return retval;
}

static char *getuidname(uid_t uid)
{
	struct passwd *pw;
	static char username[32];

	pw = getpwuid(uid);
	if (pw == NULL)
		return NULL;

	strncpy(username, pw->pw_name, sizeof(username));
	username[sizeof(username) - 1] = '\0';
	
	return username;
}

int main(int argc, char *argv[])
{
	char pass[MAXPASS + 1];
	char user[9];
        int n = 0;
	int retval = UNIX_FAILED;
        char c;

	/*
	 * Catch or ignore as many signal as possible.
	 */
	setup_signals();

        if (argc != 2) {
            fprintf(stderr, "This command takes one argument - the root of vserver.\n");
            return UNIX_FAILED;
        }

	/* read the userid */

        for (n=0; n<=8; n++) {
            c = getchar();
            if (c == EOF || c == ':')
                break;
            user[n] = c;
        }
        user[n] = '\0';

        if (n == 0 || c == EOF)
            return UNIX_FAILED;

	/* read the password from stdin */

        for (n=0; n < MAXPASS; n++) {
            if ((c = getchar()) == EOF)
                break;
            pass[n] = c;
        }
        pass[n] = '\0';

	if (n == 0) {	/* is it a valid password? */
		_log_err(LOG_DEBUG, "no password supplied");
	} else {

            /* chroot to vserver */
            if (chroot(argv[1]) != 0) {
                perror("Could not chroot");
                return UNIX_FAILED;
            }

            /* does pass agree with the official one? */
            retval = _unix_verify_password(user, pass, 1);
	}

	memset(pass, '\0', MAXPASS);	/* clear memory of the password */

	/* return pass or fail */
        return retval;
}

/*
 * Copyright (c) Andrew G. Morgan, 1996. All rights reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 * 
 * ALTERNATIVELY, this product may be distributed under the terms of
 * the GNU Public License, in which case the provisions of the GPL are
 * required INSTEAD OF the above restrictions.  (This clause is
 * necessary due to a potential bad interaction between the GPL and
 * the restrictions contained in a BSD-style copyright.)
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
