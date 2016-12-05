#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <netinet/tcp.h>
#include "ti.h"


struct option long_opts[] = {
        { "help",0,0,'h' },
};


void usage(int out) {
        FILE *f;

        f = (out) ? stderr : stdout;
        fprintf(f,"Usage:\n"\
                  "\t"WEARE" [[sip[:sport]]-[[dip[:dport]]\n");
	fprintf(f,"Example:\n"\
		  "\t"WEARE" 127.0.0.1:25-127.0.0.1:3953\n");
        exit(out);
}

struct idata idd;
struct chardata cdd;

int main(int argc,char **argv) {
	char c,*data;
	int oidx;
	int i = 1;
	cinfo_t *ci;

	while ((c = getopt_long(argc,argv,"hqz:",long_opts,&oidx)) != -1) {
		switch (c) {
			case 'h':
				usage(0);
			case 'q':
				break;
			case 'z':
				break;
			default:
				printf("parsing %s\n",optarg);
				break;
			

		}
		++i;
		if (optarg) ++i;
	}

	data = argv[i];
	if (data) {
		if (setdata(data,&idd) < 0) {
			fprintf(stderr,"Invalid data format\n");
			exit(1);
		}
	}

	convert(&idd,&cdd); 

	ci = get_cis_from_proc(&cdd);
	if (!ci) {
		printf("No match entries\n");
		exit(0);
	}

	update_proc(ci);
	show_cis(ci);

	return 0;

}

void show_cis(cinfo_t *head) {
	cinfo_t *ci;
	struct tcp_info *ti;
	
	for (ci = head; ci; ci = ci->next) {
		ti = (struct tcp_info *) ci->info;
		if (!ti) continue;
		printf("Connection %15s:%6s",ci->sip,ci->sport);
		if (ci->state == TCP_LISTEN) {
			printf(" [LISTEN] \n");
			continue;
		}
		printf("<-> %s:%-6s pid: %-6ld%s uid: %ld [%s]\n",
			ci->dip,ci->dport,
			ci->pid,
			ci->name,
			ci->uid,
			getstate(ci->state)
		);
		printf("\tinode=%ld ca_state=%d retransmits=%d probes=%d backoff=%d options=%d s_wscale=%d r_wscale=%d rto=%d ato=%d send_mss=%d rcv_mss=%d unacked=%d sacked=%d lost=%d retrans=%d fackeds=%d last_data_sent=%d last_ack_sent=%d last_data_recv=%d last_ack_recv=%d pmtu=%d rcv_ssthresh=%d rtt=%d rttvar=%d snd_ssthresh=%d snd_cwnd=%d adv_mss=%d reordering=%d\n",
		ci->inode,
		ti->tcpi_ca_state,
		ti->tcpi_retransmits,
		ti->tcpi_probes,
		ti->tcpi_backoff,
		ti->tcpi_options,
		ti->tcpi_snd_wscale,
		ti->tcpi_rcv_wscale,
		ti->tcpi_rto,
		ti->tcpi_ato,
		ti->tcpi_snd_mss,
		ti->tcpi_rcv_mss,
		ti->tcpi_unacked,
		ti->tcpi_sacked,
		ti->tcpi_lost,
		ti->tcpi_retrans,
		ti->tcpi_fackets,
		ti->tcpi_last_data_sent,
		ti->tcpi_last_ack_sent,
		ti->tcpi_last_data_recv,
		ti->tcpi_last_ack_recv,
		ti->tcpi_pmtu,
		ti->tcpi_rcv_ssthresh,
		ti->tcpi_rtt,
		ti->tcpi_rttvar,
		ti->tcpi_snd_ssthresh,
		ti->tcpi_snd_cwnd,
		ti->tcpi_advmss,
		ti->tcpi_reordering
		);


	}
	
}

char *getstate(int state) {
	switch (state) {
		case TCP_ESTABLISHED: return "ESTABLISHED";
		case TCP_SYN_SENT: return "SYN_SENT";
		case TCP_SYN_RECV: return "SYN_RECV";
		case TCP_FIN_WAIT1: return "FIN_WAIT1";
		case TCP_FIN_WAIT2: return "FIN_WAIT2";
		case TCP_TIME_WAIT: return "TIME_WAIT";
		case TCP_CLOSE:	return "CLOSE";
		case TCP_CLOSE_WAIT: return "CLOSE_WAIT";
		case TCP_LAST_ACK: return "LAST_ACK";
		case TCP_CLOSING: return "CLOSING";
		default: return "UNKNOWN";
	}
}

void inline uc(char *data) {
	char *p;
	p = data;
	while (*p) {
		*p = toupper(*p);
		++p;
	}
}

void convert(struct idata *idd, struct chardata *cdd) {
	sprintf(cdd->sip,"%08lx",idd->sip);
	sprintf(cdd->dip,"%08lx",idd->dip);
	sprintf(cdd->sport,"%04x",idd->sport);
	sprintf(cdd->dport,"%04x",idd->dport);
	uc(cdd->sip);
	uc(cdd->dip);
	uc(cdd->sport);
	uc(cdd->dport);
	if (idd->sip) cdd->flags |= FL_SIP;
	if (idd->dip) cdd->flags |= FL_DIP;
	if (idd->sport) cdd->flags |= FL_SPORT;
	if (idd->dport) cdd->flags |= FL_DPORT;
	
}

int setdata(char *data,struct idata *idd) {
	char *ptr,*tp;
	struct in_addr ia;
	unsigned int port;


	if (strlen(data) > 53) return -1;
	ptr = strchr(data,'-');
	if (!ptr) {
		idd->dport = 0;
		idd->dip = 0;
	} else {
		*ptr++ = 0;
		tp = strchr(ptr,':');
		if (!tp) idd->dport = 0;
		else {
			*tp++ = 0;
			port = atoi(tp);
			if (port < 1 || port > 65535) return -1;
			idd->dport = (unsigned short) atoi(tp);
		}
		if (*ptr) {
			inet_aton(ptr,&ia);
			idd->dip = (unsigned long) ia.s_addr;
		} else idd->dip = 0;
	}

	ptr = strchr(data,':');
	if (!ptr) idd->sport = 0;
	else {
		*ptr++ = 0;
		port = atoi(ptr);
		
		if (port < 1 || port > 65535) 
			return -1;
		idd->sport = (unsigned short) atoi(ptr);
	}
	if (*data) {
		inet_aton(data,&ia);
		idd->sip = (unsigned long) ia.s_addr;
	} else idd->sip = 0;
	
	return 0;
}

