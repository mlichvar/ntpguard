/*
 * Copyright (C) 2025  Miroslav Lichvar <mlichvar0@gmail.com>
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <arpa/inet.h>
#include <assert.h>
#include <byteswap.h>
#include <errno.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include <pcap.h>

#define RATE_THRESHOLD 500.0
#define INTERVAL_THRESHOLD 1.0
#define RECORD_TIMEOUT 1.0
#define RECORD_PRIORITY_TIMEOUT 0.1
#define HASH_TABLE_SIZE ((1U << 19) - 1)

enum client_type {
	CLIENT_UNKNOWN,
	CLIENT_FORTIGATE,
	CLIENT_TIMESYNCD,
};

struct ntp_packet {
	uint8_t lvm;
	uint8_t stratum;
	int8_t poll;
	int8_t prec;
	uint32_t rdelay;
	uint32_t rdisp;
	uint32_t ref_id;
	uint64_t ref_ts;
	uint64_t orig_ts;
	uint64_t rx_ts;
	uint64_t tx_ts;
};

struct record {
	uint32_t address;
	uint16_t port;
	uint8_t client;
	uint8_t confirmed;
	uint32_t count;
	uint64_t first_rx;
	uint64_t last_rx;
	uint64_t last_tx;
};

struct detector {
	struct record *hash_table;
	struct bpf_program filter;
	int offline;
	int datalink;
	unsigned int sampling;
};

static double tv_to_d(struct timeval *tv) {
	return ((tv->tv_sec + 2208988800LLU) << 32) + tv->tv_usec * 4294.967296;
}

static double ts_to_d(uint64_t x) {
	return x / 4294967296. - 2208988800LLU;
}

static double diff_ts(uint64_t x, uint64_t y) {
	return (int64_t)(x - y) / 4294967296.;
}

static double get_us_frac(uint64_t x) {
	double y = x / 4294967296. * 1e6;
	return y - floor(y);
}

static const char *get_client_name(enum client_type client) {
	switch (client) {
		case CLIENT_FORTIGATE:
			return "fortigate";
		case CLIENT_TIMESYNCD:
			return "timesyncd";
		default:
			return "?";
	}
}

static void handle_client(struct detector *detector, struct ntp_packet *pkt,
			  uint64_t rx, uint32_t ip4, uint16_t port,
			  uint16_t ip_id, enum client_type client) {
	double last_rx_ago, first_rx_ago, rate;
	uint32_t slot, tx_frac, last_tx_frac;
	uint64_t tx = bswap_64(pkt->tx_ts);
	struct record *record;
	struct in_addr addr;
	char buf[30];
	time_t ts;

	slot = ip4 % HASH_TABLE_SIZE;
	record = &detector->hash_table[slot];
	last_rx_ago = diff_ts(rx, record->last_rx);

	if (record->count == 0 || record->address != ip4 || record->port != port ||
	    record->client != client || last_rx_ago > RECORD_TIMEOUT) {
		if (record->count != 0 && last_rx_ago >= 0.0 && last_rx_ago < RECORD_PRIORITY_TIMEOUT)
			return;

		memset(record, 0, sizeof *record);
		record->address = ip4;
		record->port = port;
		record->client = client;
		record->first_rx = rx;
		last_rx_ago = 0.0;
	}

	record->count += detector->sampling;

	tx_frac = tx << 32 >> 32;

	switch (client) {
		case CLIENT_FORTIGATE:
			if (get_us_frac(tx_frac) < 0.999) {
				record->client = CLIENT_UNKNOWN;
				break;
			}
			record->confirmed = 1;
			break;
		case CLIENT_TIMESYNCD:
			if (record->count <= detector->sampling)
				break;
			last_tx_frac = record->last_tx << 32 >> 32;
			if (tx_frac >= 1000000000 || tx < record->last_tx ||
			    abs(diff_ts(tx, record->last_tx)) > 1.0) {
				record->client = CLIENT_UNKNOWN;
				break;
			}
			if (tx_frac < last_tx_frac && last_tx_frac - tx_frac > 900000000 &&
			    tx >> 32 == (record->last_tx >> 32) + 1)
				record->confirmed = 1;
			break;
		default:
			break;
	}

	record->last_rx = rx;
	record->last_tx = tx;

	first_rx_ago = diff_ts(rx, record->first_rx);
	rate = record->count / first_rx_ago;

	if (!record->confirmed || rate < RATE_THRESHOLD || first_rx_ago < INTERVAL_THRESHOLD)
		return;

	addr.s_addr = htonl(ip4);
	ts = ts_to_d(rx);

	strftime(buf, sizeof buf, "%FT%TZ", gmtime(&ts));
	printf("%s %s port=%d rate=%.0f client=%s\n",
	       buf, inet_ntoa(addr), port, rate, get_client_name(client));

	record->count = 0;
}

static void process_ntp_packet(struct detector *detector,
			       struct ntp_packet *pkt,
			       struct timeval *tv, uint32_t ip4,
			       uint16_t port, uint16_t ip_id) {
	enum client_type client = CLIENT_UNKNOWN;

	if ((pkt->lvm & 0x7) != 3)
		return;

	if ((pkt->lvm == 0xdb || pkt->lvm == 0xe3) &&
	    pkt->stratum == 0 &&
	    pkt->poll == 4 &&
	    pkt->prec == -6 &&
	    pkt->rdelay == htonl(1U << 16) &&
	    pkt->rdisp == htonl(1U << 16) &&
	    pkt->ref_id == 0 &&
	    pkt->ref_ts == 0 &&
	    pkt->orig_ts == 0 &&
	    pkt->rx_ts == 0)
		client = CLIENT_FORTIGATE;
	else if (pkt->lvm == 0x23 &&
	    pkt->stratum == 0 &&
	    pkt->poll == 0 &&
	    pkt->prec == 0 &&
	    pkt->rdelay == 0 &&
	    pkt->rdisp == 0 &&
	    pkt->ref_id == 0 &&
	    pkt->ref_ts == 0 &&
	    pkt->orig_ts == 0 &&
	    pkt->rx_ts == 0)
		client = CLIENT_TIMESYNCD;
	else
		return;

	handle_client(detector, pkt, tv_to_d(tv), ip4, port, ip_id, client);
}

static void process_packet(u_char *user, const struct pcap_pkthdr *hdr, const u_char *pkt) {
	uint16_t src_port, dst_port;
	uint32_t i, ip4_addr, len;
	struct detector *detector = (struct detector *)user;
	struct timeval tv;

	tv.tv_sec = hdr->ts.tv_sec;
	tv.tv_usec = hdr->ts.tv_usec;

	if (detector->offline && !pcap_offline_filter(&detector->filter, hdr, pkt))
		return;

	len = hdr->caplen;

	switch (detector->datalink) {
		case DLT_EN10MB:
			/* Check ethertype for IPv4 */
			if (!(pkt[12] == 0x08 && pkt[13] == 0x00))
				return;

			/* Skip ethernet header */
			if (len < 14)
				return;
			pkt += 14, len -= 14;

			break;
		case DLT_RAW:
			break;
		default:
			fprintf(stderr, "Unsupported datalink %s\n",
				pcap_datalink_val_to_name(detector->datalink));
			exit(4);
	}

	/* Check IP header */

	if (len < 20)
		return;

	switch (pkt[0] >> 4) {
		case 4:
			/* IPv4 address */
			memcpy(&ip4_addr, &pkt[12], sizeof ip4_addr);

			/* Check for UDP */
			if (pkt[9] != 17)
				return;

			/* Skip IP header */
			i = (pkt[0] & 0xf) * 4;
			if (len < i)
				return;
			pkt += i, len -= i;

			break;
		default:
			return;
	}

	/* Check UDP port */
	if (len < 8)
		return;

	src_port = ntohs(*(uint16_t *)&pkt[0]);
	dst_port = ntohs(*(uint16_t *)&pkt[2]);
	if (src_port != 123 && dst_port != 123)
		return;

	/* Skip UDP header */
	pkt += 8, len -= 8;

	/* Check NTP header */
	if (len < 48)
		return;

	process_ntp_packet(detector, (struct ntp_packet *)pkt, &tv,
			   ntohl(ip4_addr), src_port, 0);
}

static void print_help(char *name) {
	fprintf(stderr, "Usage: %s [-b <bufsize>] [-i <iface>|-] [-s <sampling>]\n", name);
}

int main(int argc, char **argv) {
	char ebuf[PCAP_ERRBUF_SIZE], filter[128], *iface = "eth0";
	int s, opt, bufsize = 256;
	struct detector detector;
	pcap_t *p;

	setvbuf(stdout, NULL, _IONBF, 0);

	memset(&detector, 0, sizeof detector);
	detector.sampling = 16;

	while ((opt = getopt(argc, argv, "b:i:s:")) != -1) {
		switch (opt) {
			case 'b':
				bufsize = atoi(optarg);
				break;
			case 'i':
				iface = optarg;
				break;
			case 's':
				detector.sampling = atoi(optarg);
				break;
			default:
				print_help(argv[0]);
				return 1;
		}
	}

	if (optind < argc) {
		print_help(argv[0]);
		return 1;
	}

	detector.offline = !strcmp(iface, "-");

	/* Prepare a filter matching every sampling-th fortigate or timesyncd
	   request to minimize the CPU usage */
	snprintf(filter, sizeof filter,
		 "dst port 123 and udp[8]&3=3 and ip[4:2]%%%u=0 and "
		 "(udp[11]=250 or udp[8:4]=0x23000000)",
		 detector.sampling);

	if (!detector.offline) {
		if (!(p = pcap_create(iface, ebuf))) {
			fprintf(stderr, "pcap_create() failed: %s\n", ebuf);
			return 2;
		}

		if (pcap_set_promisc(p, 1) ||
		    pcap_set_timeout(p, 100) ||
		    pcap_set_buffer_size(p, bufsize * 1024) ||
		    pcap_set_snaplen(p, 128) ||
		    pcap_activate(p) ||
		    pcap_compile(p, &detector.filter, filter, 1, PCAP_NETMASK_UNKNOWN) ||
		    pcap_setfilter(p, &detector.filter)) {
			fprintf(stderr, "pcap start failed on interface %s", iface);
			pcap_perror(p, "");
			return 3;
		}
	} else {
		if (!(p = pcap_open_offline("-", ebuf))) {
			fprintf(stderr, "%s\n", ebuf);
			return 2;
		}

		if (pcap_compile(p, &detector.filter, filter, 1, PCAP_NETMASK_UNKNOWN)) {
			pcap_perror(p, "");
			return 3;
		}
	}

	detector.datalink = pcap_datalink(p);

	detector.hash_table = calloc(sizeof (struct record), HASH_TABLE_SIZE);

	while (1) {
		s = pcap_dispatch(p, 1, process_packet, (u_char *)&detector);
		if (s == -1 || (!s && detector.offline))
			break;

	}

	free(detector.hash_table);

	pcap_freecode(&detector.filter);
	pcap_close(p);

	return 0;
}
