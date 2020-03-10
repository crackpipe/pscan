/**
 * +---------------------------------------------------------+
 * name: pscan
 * description: port scanner
 * version: v0.9
 * author: crtube
 * license: MIT (see LICENSE)
 * compile with: gcc pscan.c -o pscan -lpthread
 * +---------------------------------------------------------+
 * todo:
 * - implement ping
 * - parse arguments better
 * - create a timeout method for TCP
 * - consider optimizing port scanning method
 * +---------------------------------------------------------+
**/

#define DETAILS 16
#define VERSION "v0.9"

#include <poll.h>
#include <stdio.h>
#include <netdb.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>

typedef struct {
	char* addr;
	int min_range;
	int max_range;
} scanData;

char* bnr = "pscan %s by crtube\n"
				"do 'sed %dq pscan.c' to check details\n"
				"not for human consumption\n";

void dlog(char* msg, int level) {
	switch(level) {
		case -1:
			printf("[debug] %s\n", msg);
			break;
		case 0:
			printf("[log] %s\n", msg);
			break;
		case 1:
			printf("[warn] %s\n", msg);
			break;
		case 2:
			printf("[error] %s\n", msg);
			break;
		default:
			printf("[log] %s\n", msg);
			break;	
	}
}

scanData* createScanData(char* addr, int min, int max) {
	scanData* sd = malloc(sizeof(scanData));

	struct hostent* h = gethostbyname(addr);
	struct in_addr** hl = (struct in_addr**)h->h_addr_list;

	sd->addr = inet_ntoa(*hl[0]);
	sd->min_range = min;
	sd->max_range = max;

	return sd;
}

void destroyScanData(scanData* sd) {
	free(sd);
}

void banner() {
	printf(bnr, VERSION, DETAILS);
}

int connTimeoutTCP(int fd, struct sockaddr_in d) {
	// TODO
}

void* scanTCP(void* arg) {
	dlog("starting TCP scan", 1);

	int fd;
	scanData* sd = (scanData*)arg;
	struct sockaddr_in d;
	struct timeval t;
	struct servent* serv = NULL;

	t.tv_sec = 1;
	t.tv_usec = 0;

	memset(&d, 0, sizeof(d));
	
	d.sin_family = AF_INET;
	d.sin_addr.s_addr = inet_addr(sd->addr);
	
	for(int i = sd->min_range; i != sd->max_range + 1; i++) {
		d.sin_port = htons(i);
			
		if((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1)
			dlog("socket fail", 2);

		if(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (char*)&t, sizeof(t)) == -1)
			dlog("sock opt fail", 2);

		if(setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (char*)&t, sizeof(t)) == -1)
			dlog("sock opt fail", 2);

		if(connect(fd, (struct sockaddr*)&d, sizeof(struct sockaddr)) != -1) {
			serv = getservbyport(htons(i), "tcp"); 
			if(serv != NULL)
				printf("TCP port %d open - service %s\n", i, serv->s_name);
			else
				printf("TCP port %d open - service unknown\n", i);
		}

		close(fd);
	}

	dlog("completed TCP scan", 1);
	return NULL;
}

int sendUDP(int fd, struct sockaddr_in d) {
	if(sendto(fd, "A", 1, 0, (struct sockaddr*)&d, sizeof(d)) != -1)
		return 0;

	return -1;
}

int recvUDP(int fd) {
	char buf[32];
	memset(&buf, '\0', sizeof(buf));
	int ilen;
	struct ip* ih = NULL;
	struct icmp* icmph = NULL;

	struct pollfd p[1];

	// thanks beej
	p[0].fd = fd;
	p[0].events = POLLIN;

	while(1) {
		int ne = poll(p, 1, 0);

		if((ne = poll(p, 1, 1000)) == -1) {
			dlog("poll error", 2);
			return -1;
		} 

		if(ne != 0) {
			if(p[0].revents & POLLIN) {
				// recvfrom (unreach)
				if(recvfrom(p[0].fd, buf, sizeof(buf), 0, NULL, NULL) == -1)
					return -1;

				ih = (struct ip*)buf;
				ilen = ih->ip_hl << 2;

				icmph = (struct icmp*)(buf + ilen);

				if(icmph->icmp_type == ICMP_UNREACH && icmph->icmp_code == ICMP_UNREACH_PORT)
					return 0;
				else
					return 1;
			}
		} else {
			return 2;
		}
	}
}

void* scanUDP(void* arg) {
	dlog("starting UDP scan", 1);
	
	int fd, rfd;
	int yes = 1;
	int code;
	struct servent* serv;
	struct sockaddr_in d;
	struct timeval t;
	struct msghdr* h;
	scanData* sd = (scanData*)arg;

	t.tv_sec = 1;
	t.tv_usec = 0;

	memset(&d, 0, sizeof(d));	
	d.sin_family = AF_INET;
	d.sin_addr.s_addr = inet_addr(sd->addr);

	int i = sd->min_range ? sd->min_range > 0 : sd->min_range + 1;

	for(; i != sd->max_range + 1; i++) {
		d.sin_port = htons(i);

		if((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
			dlog("standard socket create fail", 2);

		if((rfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1)
			dlog("icmp socket create fail. maybe not root?", 2);

		if(sendUDP(fd, d) == -1)
			printf("udp send fail @ %d\n", i);

		code = recvUDP(rfd);
		serv = getservbyport(htons(i), "udp");

		switch(code) {
			case -1:
				dlog("icmp recv fail", 2);
				break;
			case 1:
				if(serv != NULL)
					printf("UDP port %d open - service %s\n", i, serv->s_name);
				else
					printf("UDP port %d open - service unknown\n", i);

				break;
			case 2:
				if(serv != NULL)
					printf("UDP port %d blocked - service %s\n", i, serv->s_name);
				else
					printf("UDP port %d blocked - service unknown\n", i);
				break;
			default:
				break;
		}

		close(fd);
		close(rfd);
	}

	dlog("completed UDP scan", 1);
	return NULL;
}

int main(int argc, char** argv) {
	banner();

	scanData* sd = NULL;
	
	if(argc < 4) {
		printf("usage: %s <host> <start> <end>\n", argv[0]);
		exit(0);
	} else {
		sd = createScanData(argv[1], atoi(argv[2]), atoi(argv[3]));
		printf("scanning ports %d-%d on host %s\n", sd->min_range, sd->max_range, sd->addr);
	
		pthread_t tcp, udp;

		pthread_create(&tcp, NULL, scanTCP, sd);
		pthread_create(&udp, NULL, scanUDP, sd);

		pthread_join(tcp, NULL);
		pthread_join(udp, NULL);
	}

	return 0;
}
