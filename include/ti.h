#ifndef _TI_H
#define _TI_H

#define WEARE "ti"

#define PROCDIR			"/proc"
#define TCP_CONNECTIONS_FILE 	PROCDIR"/net/tcp"

struct idata {
	unsigned long sip,dip;
	unsigned short sport,dport;
};

#define FL_SIP		0x1
#define FL_DIP		0x2
#define FL_SPORT	0x4
#define FL_DPORT	0x8

struct chardata {
	char sip[16],dip[16];
	char sport[5],dport[5];
	unsigned short flags;
};

#define LINE_BUF		4096
#define NAME_MAX_LEN		256

typedef struct cinfo_s {
	char *sip,*dip;
	char *sport,*dport;
	void *info;
	char *name;
	int state;
	unsigned long pid,uid;
	unsigned long inode;
	unsigned long retransmit;
	unsigned int cwnd, rto;
	int ssthresh;
	struct cinfo_s *next;
} cinfo_t;

cinfo_t *get_cis_from_proc(struct chardata *);
cinfo_t *alloc_ci(void);
int setdata(char *,struct idata *);
void convert(struct idata *, struct chardata *);
void inline uc(char *);
void usage(int);
void init_cinfos(void);
void show_cis(cinfo_t *);
char *ascii_it(char *,short);
void update_proc(cinfo_t *);
cinfo_t *get_ci_by_inode(cinfo_t *,unsigned long);
char *proc_get_name(char *);
void fill_tcp(unsigned long, unsigned int, void **);
int getlen(char *);
char *getstate(int);

#define TYPE_IP		0x0
#define TYPE_PORT	0x1




#endif
