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
 * $Id: pace.c,v 1.1 2004/10/08 02:07:43 grisha Exp $
 * 
 * This file is based on unix_chkpwd.c by Andrew G. Morgan, the
 * Copyright for which is at the bottom of this file.
 *
 * This program expects userid:password from stdin and its exit
 * status of 0 indicates that the password is OK.
 *
 */

/*
 * This is a silly little program that can be used as a pipe to
 * slowdown throughput. We use it to pace local backups to they don't
 * drive the load through the roof.
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int
main()
{   
  char buf[64000];
  int n;

  while (1) {
    n = read(0, buf, sizeof(buf));
    usleep(10000);
    if (n <= 0) {
      break;
    }
    write(1, buf, n);
  }
  
  return 0;
}
        

