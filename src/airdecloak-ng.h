/*
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * is provided AS IS, WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, and
 * NON-INFRINGEMENT.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston,
 * MA 02111-1307, USA.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */

#ifndef _AIRUNDEFENSE_H_
#define _AIRUNDEFENSE_H_

#include "pcap.h"
#include "common.h"

typedef enum {false, true} BOOLEAN;

/*
typedef enum {
	CLOAKING_NOT_YET_CHECKED,
	VALID_FRAME_UNCLOAKED,
	CLOAKED_FRAME,
	CLOAKING_STATUS_TBD, // Identical SN
	DROPPED_FRAME,
	WEIRD_FRAME_TYPE
} CLOAKING_STATUS;
*/
// How far should we check for cloaked packets (backward and forward)
#define PACKET_CHECKING_LENGTH 10


#define DIRECTION_BACKWARD 0
#define DIRECTION_FORWARD 1



#define UKNOWN_FRAME_CLOAKING_STATUS -1
#define VALID_FRAME_UNCLOAKED 0
#define CLOAKED_FRAME 2
#define POTENTIALLY_CLOAKED_FRAME 1
#define DROPPED_FRAME 3

// Weird frames are rejected before being checked atm
#define WEIRD_FRAME_TYPE 100


#define FRAME_TYPE_MANAGEMENT 0
#define FRAME_TYPE_CONTROL 1
#define FRAME_TYPE_DATA 2

#define BEACON_FRAME 0x80
#define PROBE_RESPONSE 0x50
#define AUTHENTICATION 0xB0
#define ASSOCIATION_REQUEST 0x00
#define ASSOCIATION_RESPONSE 0x10
#define NULL_FRAME 0x48


#define FILTER_SIGNAL 1
#define FILTER_DUPLICATE_SN 2
#define FILTER_DUPLICATE_SN_AP 3
#define FILTER_DUPLICATE_SN_CLIENT 4
#define FILTER_CONSECUTIVE_SN 5
#define FILTER_DUPLICATE_IV 6
#define FILTER_SIGNAL_DUPLICATE_AND_CONSECUTIVE_SN 7


#define getBit(pckt, startbit) getBits(pckt, startbit, 1)
#define get_iv(packet) ((packet)->iv[0]+((packet)->iv[1] * 256)+((packet)->iv[2] *256*256))

const int PACKET_HEADER_SIZE = sizeof( struct pcap_pkthdr );

struct packet_elt_header {
	struct packet_elt *first;
	struct packet_elt *current;
	struct packet_elt *last;
	int nb_packets;
	int average_signal; // Calculate the average signal (for later)
						// Currently do it on management frames (or control frames); may change in the future.
} * _packet_elt_head;

struct packet_elt
{
    struct pcap_pkthdr header;  /* packet header */
    unsigned char   *packet;    /* packet */
    unsigned short  length;     /* packet length, just to know how much to write to the file */

    // A few interesting stuff coming from the packets
    int fromDS;
    int toDS;

    int frame_type; 			/* MGMT, CTRL, DATA */
    int frame_subtype; // Not yet filled but will do
    unsigned char version_type_subtype; // First byte

    unsigned char  source[6];
    unsigned char  destination[6];
    unsigned char  bssid[6];

    int sequence_number;
    int fragment_number;
    unsigned char iv[3];
    unsigned char key_index;
    unsigned char icv[4];
    int signal_quality;
    int retry_bit;
    int more_fragments_bit;

    //int packet_number;			/* packet number */

    int is_cloaked;
    int is_dropped; // Do we have to drop this frame?

	int complete; // 0: no, 1: yes

    struct packet_elt * next;
    struct packet_elt * prev;
};

// Not already used (partially maybe)
struct decloak_stats
{
    unsigned long nb_read;      /* # of packets read       */
    unsigned long nb_wep;       /* # of WEP data packets   */
    unsigned long nb_bad;       /* # of bad data packets   */
    unsigned long nb_wpa;       /* # of WPA data packets   */
    unsigned long nb_plain;     /* # of plaintext packets  */
    unsigned long nb_filt_wep;  /* # of filtered WEP pkt  */
    unsigned long nb_cloak_wep; /* # of cloaked WEP pkt  */
};

extern char * getVersion(char * progname, int maj, int min, int submin, int svnrev, int beta, int rc);
extern int getmac(char * macAddress, int strict, unsigned char * mac);
extern char * mac2string(unsigned char * mac);
extern int maccmp(unsigned char *mac1, unsigned char *mac2);

void usage(void);
int getBits(unsigned char b, int from, int length);
FILE * openfile(const char * filename, const char * mode, int fatal);
BOOLEAN write_packet(FILE * file, struct packet_elt * packet);
FILE * init_new_pcap(const char * filename);
FILE * open_existing_pcap(const char * filename);
BOOLEAN read_packets(void);
BOOLEAN initialize_linked_list(void);
BOOLEAN add_node_if_not_complete(void);
void set_node_complete(void);
void remove_last_uncomplete_node(void);
struct packet_elt * getPacketNr(int position);
char * iv2string(unsigned char * iv);
char * icv2string(unsigned char * icv);
void print_packet(struct packet_elt * packet);
void reset_current_packet_pointer(void);
BOOLEAN reset_current_packet_pointer_to_ap_packet(void);
BOOLEAN reset_current_packet_pointer_to_client_packet(void);
BOOLEAN next_packet_pointer(void);
BOOLEAN next_packet_pointer_from_ap(void);
BOOLEAN next_packet_pointer_from_client(void);
BOOLEAN prev_packet_pointer(void);
int compare_SN_to_current_packet(struct packet_elt * packet);
BOOLEAN current_packet_pointer_same_fromToDS_and_source(struct packet_elt * packet);
BOOLEAN prev_packet_pointer_same_fromToDS_and_source(struct packet_elt * packet);
BOOLEAN next_packet_pointer_same_fromToDS_and_source(struct packet_elt * packet);
BOOLEAN prev_packet_pointer_same_fromToDS_and_source_as_current(void);
BOOLEAN next_packet_pointer_same_fromToDS_and_source_as_current(void);
BOOLEAN write_packets(void);
BOOLEAN print_statistics(void);
char * status_format(int status);
int get_average_signal_ap(void);

// Check for cloaking functions
BOOLEAN check_for_cloaking(void); // Main cloaking check function
#define CFC_base_filter() CFC_with_valid_packets_mark_others_with_identical_sn_cloaked()
int CFC_with_valid_packets_mark_others_with_identical_sn_cloaked(void);
int CFC_mark_all_frames_with_status_to(int original_status, int new_status);
int CFC_filter_signal(void);
int CFC_filter_duplicate_sn_ap(void);
int CFC_filter_duplicate_sn_client(void);
int CFC_filter_duplicate_sn(void);
int CFC_filter_consecutive_sn(void);
int CFC_filter_consecutive_sn_ap(void);
int CFC_filter_consecutive_sn_client(void);
int CFC_filter_duplicate_iv(void);
int CFC_filter_signal_duplicate_and_consecutive_sn(void);

/*
const char usage[] =
"\n"
"  %s - (C) 2008 Thomas d\'Otreppe\n"
"  https://www.aircrack-ng.org\n"
"\n"
"  usage: airundefense-ng <filename> <BSSID>\n"
"\n";
*/

#endif
