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
#include "ti.h"

static void _update_proc(char *, cinfo_t *);

cinfo_t *alloc_ci(void) {
	cinfo_t *ci;

	ci = (cinfo_t *) malloc(sizeof(cinfo_t));
	if (!ci) {
		fprintf(stderr,"Can't alloc cinfo struct\n");
		exit(1);
	}

	ci->cwnd = ci->rto = ci->ssthresh = 0;
	ci->next = NULL;
	return ci;
}

cinfo_t *get_cis_from_proc(struct chardata *cdd) {
	cinfo_t *ci,*pci,*mci;
	char dbuf[32],buf[512],*ptr;
	int num,timeout,header_met = 0;
	struct chardata mdd;
	unsigned long uid,inode,rtr;
	unsigned int rto,cwnd,db;
	unsigned long flags;
	int ssthresh,state;
	void *db1;
	FILE *f;

	
	pci = NULL;
	mci = ci = alloc_ci();
	f = fopen(TCP_CONNECTIONS_FILE,"r");
	if (!f) {
		fprintf(stderr,"Can't open %s\n",TCP_CONNECTIONS_FILE);
		exit(1);
	}

	flags = cdd->flags;
	while ((ptr = fgets(buf,512,f)) != NULL) {
		if (!header_met) {
			header_met = 1;
			continue;
		}
		ssthresh = rto = cwnd = 0;
		sscanf(ptr,"%4d: %8s:%4s %8s:%4s %x %s%s %lx %lu %d %lu %u %p %u %u %u %u %d",
			&num,
			mdd.sip,mdd.sport,
			mdd.dip,mdd.dport,
			&state,
			dbuf,dbuf,
			&rtr,
			&uid,
			&timeout,
			&inode,
			&db,&db1,
			&rto,
			&db,&db,
			&cwnd,
			&ssthresh
		);

		if (flags & FL_SIP) if (strcmp(mdd.sip,cdd->sip)) continue;
		if (flags & FL_DIP) if (strcmp(mdd.dip,cdd->dip)) continue;
		if (flags & FL_SPORT) if (strcmp(mdd.sport,cdd->sport)) continue;
		if (flags & FL_DPORT) if (strcmp(mdd.dport,cdd->dport)) continue;
		
		ci->sip = ascii_it(mdd.sip,TYPE_IP);
		ci->dip = ascii_it(mdd.dip,TYPE_IP);
		ci->sport = ascii_it(mdd.sport,TYPE_PORT);
		ci->dport = ascii_it(mdd.dport,TYPE_PORT);
		ci->state = state;
		ci->retransmit = rtr;
		ci->uid = uid;	
		ci->inode = inode;
		ci->rto = rto;
		ci->cwnd = cwnd;
		ci->ssthresh = ssthresh;

		if (!pci) pci = ci;
		else {
			pci->next = ci;
			pci = ci;
			ci = alloc_ci();		
		}
	}

	if (pci) pci->next = NULL;
	else return NULL;
	fclose(f);
	return mci;
}

char *ascii_it(char *data,short type) {
	char *rv;
	int mem;
	int octs[4],port;

	mem = (type == TYPE_IP) ? 16 : 5;
	rv = (char *) malloc(sizeof(char) * mem);
	if (!rv) {
		fprintf(stderr,"Can't alloc memory\n");
		exit(1);
	}	
	if (type == TYPE_IP) {
		sscanf(&data[0],"%2x",&octs[3]);
		sscanf(&data[2],"%2x",&octs[2]);
		sscanf(&data[4],"%2x",&octs[1]);
		sscanf(&data[6],"%2x",&octs[0]);
		sprintf(rv,"%d.%d.%d.%d",octs[0],octs[1],octs[2],octs[3]);
	} else {
		sscanf(&data[0],"%4x",&port);
		sprintf(rv,"%d",port);
	}
	return rv;
}

static void _update_proc(char *charpid, cinfo_t *ci) {
	DIR *dir;
	struct dirent *de;
	char pbuf[PATH_MAX],*ptr;
	char lbuf[PATH_MAX],*sp;
	ssize_t sz;
	int len;
	unsigned long inode;
	unsigned int fd;
	cinfo_t *lci;

	ptr = pbuf;
	sprintf(pbuf,PROCDIR"/%s/fd/",charpid);
	len = strlen(pbuf);
	dir = opendir(pbuf);
	if (!dir) {
		fprintf(stderr,"Warning: Can't open dir %s [%s]\n",pbuf,strerror(errno));
		return;
	}

	while ((de = readdir(dir)) != NULL) {
		if (!isdigit(de->d_name[0])) continue;
		if (de->d_type != DT_LNK) {
			fprintf(stderr,"Some errors in procfs, %s, skipping...\n",pbuf);
			continue;
		}
		strncpy(ptr + len, de->d_name, de->d_reclen);
		sz = readlink(ptr,lbuf,PATH_MAX);
		if (sz < 0) {
			fprintf(stderr,"Warning: Can't readlink %s, skipping...\n",ptr);
			continue;
		}

		/* Capture potentially ']' at the end */
		lbuf[sz-1] = 0;
		if (strncmp(lbuf,"socket:[",8)) continue;
		sp = &lbuf[8];
		inode = atoi(sp);

		lci = get_ci_by_inode(ci,inode);
		if (lci) {
			fd = atoi(de->d_name);
			lci->pid = atoi(charpid);
			lci->name = proc_get_name(charpid);
			fill_tcp(lci->pid,fd,&lci->info);
		}
	}

	closedir(dir);
}

char *proc_get_name(char *charpid) {
	FILE *f;
	char buf[PATH_MAX],*ptr;
	char nb[LINE_BUF],*name;
	int dub;


	sprintf(buf,PROCDIR"/%s/stat",charpid);
	f = fopen(buf,"r");
	if (!f) return NULL;


	ptr = fgets(nb,LINE_BUF,f);
	if (!ptr) return NULL;

	name = (char *) malloc(sizeof(char) * NAME_MAX_LEN);
	if (!name) {
		fprintf(stderr,"Alloc error\n");
		exit(1);
	}
	
	sscanf(ptr,"%d %s",&dub,name);
	fclose(f);

	return name;
}

cinfo_t *get_ci_by_inode(cinfo_t *base, unsigned long inode) {
	cinfo_t *ci;

	for (ci = base; ci; ci = ci->next) {
		if (ci->inode == inode) return ci;
	}
	return NULL;
}

void update_proc(cinfo_t *ci) {
	DIR *dir;
	struct dirent *de;

	dir = opendir(PROCDIR);
	if (!dir) {
		fprintf(stderr,"Can't open procdir\n");
		exit(1);
	}

	while ((de = readdir(dir)) != NULL) {
		if (!isdigit(de->d_name[0])) continue;
		_update_proc(de->d_name,ci);
	}

	closedir(dir);
}
