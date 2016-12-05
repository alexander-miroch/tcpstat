#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <linux/tcp.h>
#include <errno.h>

#include "ti.h"
#include "sc.h"

extern void go(void);

void fill_tcp(unsigned long pid, unsigned int fd, void **buf) {
	long *tp,tpb[DATA_BUF];
	long ptr,begin;
	struct  user_regs_struct data, sdata;
	int error, len, i = 0;
	char *qp,qbuf[STACK_PLACE];
	unsigned short *pfd;

	bzero(tpb,DATA_BUF);
	if ((error = ptrace(PTRACE_ATTACH, pid, NULL, NULL))) {
		fprintf(stderr,"Warning: can't attach pid %ld, skipping\n",pid);
		return;
	}

	waitpid(pid,NULL,0);
	if ((error = ptrace(PTRACE_GETREGS, pid, NULL, &data))) {
		fprintf(stderr,"Warning: can't get regs pid %ld, %d skipping\n",pid,errno);
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
		return;
        }

	memcpy(&sdata,&data,sizeof(struct user_regs_struct));
	ptr = begin = data.rsp - STACK_PLACE;
	data.rip = (long) begin + 2;
	if ((error = ptrace(PTRACE_SETREGS, pid, NULL, &data))) {
		fprintf(stderr,"Warning: can't set regs pid %ld, skipping\n",pid);
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
		return;
	}

	qp = qbuf;
	len = getlen((char *) go);
	memcpy(qbuf,(char *)go,len);
	pfd = (unsigned short *) &qbuf[INJECT_OFFSET];
	*pfd = fd;
	while (i < len) {
		error = ptrace(PTRACE_POKETEXT, pid, ptr, (long) *(long *)(qp + i));
		if (error) {
			fprintf(stderr,"Warning: can't poketext, pid %ld, skipping\n",pid);
			ptrace(PTRACE_SETREGS, pid, NULL, &sdata);
			ptrace(PTRACE_DETACH, pid, NULL, NULL);
			return;
		}
		i += sizeof(long);
		ptr += sizeof(long);
	}

	error = ptrace(PTRACE_CONT,pid,NULL,NULL);
	if (error) {
		fprintf(stderr,"Warning: can't continue, pid %ld, skipping\n",pid);
		ptrace(PTRACE_SETREGS, pid, NULL, &sdata);
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
		return;
	}
	waitpid(pid,NULL,0);
	if ((error = ptrace(PTRACE_GETREGS, pid, NULL, &data))) {
		fprintf(stderr,"Warning: can't get regs after cont, pid %ld, skipping\n",pid);
		ptrace(PTRACE_SETREGS, pid, NULL, &sdata);
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
		return;
        }

	if (data.rax != 0) {
		fprintf(stderr,"Warning: getsockopt failed with %ld pid %ld [PERHAPS THE STACK IS NOT EXECUTABLE], skipping\n",data.rax,pid);
		ptrace(PTRACE_SETREGS, pid, NULL, &sdata);
		ptrace(PTRACE_DETACH, pid, NULL, NULL);
		return;
	}
	
	i = 0;
	ptr = data.rsp - DATA_OFFSET;
	tp = tpb;
	while (i < SZTCP/sizeof(long)) {
		*tp = ptrace(PTRACE_PEEKTEXT,pid,ptr,NULL);
		++tp, ++i;
		ptr += sizeof(long);	
	}
	
	*buf = (char *) malloc (sizeof(char) * SZTCP);
	if (*buf) {
		memcpy(*buf,tpb,SZTCP);
	} else {
		fprintf(stderr,"Warning: memory alloc error\n");
	}

	ptrace(PTRACE_SETREGS, pid, NULL, &sdata);
	ptrace(PTRACE_DETACH, pid, NULL, NULL);
}


int getlen(char *p) {
        char *b;
        int i = 0;

        b = p;
        while (1) {
                if (*b == 'E' && *(b+1) == 'N' && *(b+2) == 'D') break;
                ++i, ++b;
        }
        return i;
}

