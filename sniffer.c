#include <time.h>
#include <pcre.h>
#include <stdio.h>
#include <stdlib.h>
#include <regex.h>
#include <pcap.h>
#include "IPoffset.h"

int packet_counter, match_count;

#define RECORDER 1
#define PRINT 1
#define PRINT_PACKET 1
#define OFFLINE_READ 0
#define LOGGING 0

char *prefix;
FILE *output;
char *MATCH;
/* Check for cookie in packet */
int cookie_test (const u_char *packet, int length) {

	/* Declare PCRE components */
	char *pattern = "Cookie: ";
	const char *error;
	#define OUTCOUNT 30
	int output [OUTCOUNT];
	int rc, erroffset;

	/* Compile PCRE */
	pcre *re = pcre_compile (pattern, 0, &error, &erroffset, NULL);

	/* Execute expression */
	rc = pcre_exec (re, NULL, packet, length, 0, 0, output, OUTCOUNT);

	return (rc != PCRE_ERROR_NOMATCH);
}

/* Check for GET requests */
int GET_test (const u_char *packet, int length) {

	// Pattern
	char *pattern = "Get";
	return 1;
}


/* See all doubleclick.net traffic */
int doubleclick_test (const u_char *packet, int length) {

	/* Declare PCRE componentsf */
	char *pattern = "GET /";
	const char *error;
	#define OUTCOUNT 30
	int ovector [OUTCOUNT];
	int rc, erroffset;

	/* Compile PCRE */
	pcre *re = pcre_compile (pattern, 0, &error, &erroffset, NULL);
	if (!re) {
		printf("PCRE compile failed.\n");
	}
	/* Execute expression */
	rc = pcre_exec (re, NULL, packet, length, 0, 0, ovector, OUTCOUNT);
	return (rc != PCRE_ERROR_NOMATCH);	
}

/* If Referer is missing, print the packet. */
int referer_test (const u_char *packet, int length) {

	/* Declare PCRE componentsf */
	char *GET_pttrn = "GET /"; 
	char *Ref_pttrn = "(Referer:[^\\n]*)";
	const char *error;
	#define OUTCOUNT 30
	int ovector [OUTCOUNT];
	int rc, erroffset;

	/* Compile PCRE */
	pcre *GET_pcre = pcre_compile (GET_pttrn, 0, &error, &erroffset, NULL);
	pcre *Ref_pcre = pcre_compile (Ref_pttrn, 0, &error, &erroffset, NULL);
	
	/* Execute expression */
	rc = pcre_exec (Ref_pcre, NULL, packet, length, 0, 0, ovector, OUTCOUNT);
/*	
	if (rc != PCRE_ERROR_NOMATCH) {

		rc = pcre_exec (Ref_pcre, NULL, packet, length, 0, 0, output, OUTCOUNT);

		if (rc == PCRE_ERROR_NOMATCH)
			return 1;
	}
	
	return 0;
*/
	if (rc != PCRE_ERROR_NOMATCH) {

		MATCH = malloc (2048 * sizeof(char));
		char *match = malloc (2048 * sizeof (char));
		int i = 0; 
			sprintf (match, "%.*s\n", ovector[2*i+1] - ovector[2*i], packet + ovector[2*i]);
		sprintf(MATCH, "    %s", match);
		return 1;
	}
	
	return 0;
}

int dispatch_tests (const u_char *packet, const int length) {

	/* Send packet to test and return result */ 
	int (*test)(const u_char*, int);

	test = &doubleclick_test;

	if (test(packet, length)) {
		match_count++;
		return 1;
	}

	return 0;
}

void packet_handler (u_char *dump, const struct pcap_pkthdr *header, 
	const u_char *packet_data) {

	#define OFFSET 54 /* TCP Header data */ 
	int counter = ++packet_counter;	
	/* Discard packets with no data */
	if (header->caplen < OFFSET)
		return;
	/* Store all readable data */
	char *packet = malloc ((header->caplen) * sizeof (char));

	int i;
	for (i = 0; i < header->caplen; i++)  
		/* Get all printable characters */
		if (i < OFFSET)
			continue;
		else if (isprint(packet_data[i]) || packet_data[i] == '\r' || packet_data[i] == '\n') 
			packet[i - OFFSET] = packet_data[i];
		else 
			packet[i - OFFSET] = '.';
	packet[i - OFFSET] = '\0';

	/* Check for relevant ad information */

	if (dispatch_tests (packet, i - OFFSET) && PRINT ) {
		printf(" %02i -> %li\n", counter, header->ts.tv_usec);
		if (PRINT_PACKET) {
			printf("%s", packet);
			print_packet_IP (packet_data);
		}
		printf("%s", MATCH);
		printf("\n\n");

	} else if (PRINT_PACKET) {
		
		printf(" %02i -> %li\n", counter, header->ts.tv_usec);
		printf("%s\n\n", packet);
	}	

	if (LOGGING) {


	}

	if (!OFFLINE_READ)
		pcap_dump (dump, header, packet_data);
	free (packet);

}


int main (int argc, char **argv) {
	MATCH = NULL;
	packet_counter = 0, match_count = 0;
	double sum = 0;
	if (OFFLINE_READ) {
		/* Get our packet capture */
		char *file = "personal.pcap";
		int i;
		for (i = 1; i <= argc; i++) {
			if (argc > 1) 
				if (i == argc)
					break;
				else
					file = argv[i];

			char errbuf[PCAP_ERRBUF_SIZE];
			pcap_t *pcap = pcap_open_offline (file, errbuf);

			if (pcap == NULL) {
				printf ("Error opening pcap: %s\n", errbuf);
				continue;	
			}

			/* Read through file */
			pcap_loop (pcap, 0, packet_handler, NULL);
			printf ("Sniff... sniff.... %i total packets counted. %.004f rate. [%s]\n", packet_counter, (100.0 * match_count) / packet_counter, file);
			sum += (100.0 * match_count) / packet_counter;

			packet_counter = 0;
			match_count = 0;
		}
		printf ("%d packets counter. Avg. rate [%.004f].\n", argc, sum / argc);
	} else {

		/* Start live capture */
		char *dev = NULL;
		char errbuf[PCAP_ERRBUF_SIZE];
		pcap_t *stream;
		pcap_dumper_t *pcap_dumper = NULL;

		/* Look up capture device */
		dev = pcap_lookupdev (errbuf);
		if (dev == NULL) {
			printf ("Error - Can't find device: %s\n", errbuf);
			exit(1);
		}

		char filter_exp[] = "tcp port http";		/* filter expression [3] */
		struct bpf_program fp;			/* compiled filter program (expression) */
		bpf_u_int32 mask;			/* subnet mask */
		bpf_u_int32 net;                /* tcpdump.org */

		/* Get mask information */
		if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
			printf ("Couldn't get netmask - %s\n", errbuf);
			net = 0;
			mask = 0;
		}
		
		/* Open device */
		printf ("Device: %s\n\n", dev);
		stream = pcap_open_live(dev, 1518, 1, 1000, errbuf);
		if (stream == NULL) {
			printf ("Couldn't open capture: %s\n", errbuf);
			exit(1);
		}

		/* Apply TCP filter */
		if (pcap_compile(stream, &fp, filter_exp, 0, net) == -1
			|| pcap_setfilter(stream, &fp) == -1){
			printf ("Error: Could not set filter");
			exit(-1);
		}
		
		/* Number of files to record */
		int i, range = 1;
		int num_packets = 100000;

		char *filename = malloc (32 * sizeof (char));
		prefix   = malloc (32 * sizeof (char));
		char *directory = "record";

		/* Generate filenames */
		time_t rawtime;
		struct tm *ptm;
		time (&rawtime);
		ptm = gmtime (&rawtime);

		int month = ptm->tm_mon + 1;
		int day = ptm->tm_mday;

		sprintf (prefix, "%s/%02d-%02d-%d", directory, month, day, (int)rawtime);
		
		/* 'filename' is for packet capture */
		/* 'log_file' is log for alerts */

		if (argc == 2) 
			sprintf (filename, "%s/%s-%d.pcap", directory, argv[1], (int)rawtime);
		else
			sprintf (filename, "%s.pcap", prefix);

		if (LOGGING) {
			char *log_file = (char*) malloc (64 * sizeof(char));
			sprintf (log_file, "%s_log.txt", prefix);
			output = fopen (log_file, "w");
		}
		/* Save packets */	
		for (i = 0; i < range; i++) {

			printf("%s\n", filename);
			pcap_dumper = pcap_dump_open (stream, filename);
			if (pcap_dumper == NULL) {
				printf ("Error opening logfile.\n");
				exit (-1);
			}

			/* Begin capture */
			pcap_loop (stream, num_packets, packet_handler, (unsigned char *)pcap_dumper);
		}
		/* Clean-up */
		pcap_freecode (&fp);
		pcap_close(stream);




	}
	return 0;
}
