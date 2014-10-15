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

#ifndef _AIRODUMP_NG_H_
#define _AIRODUMP_NG_H_

#include <stdint.h>
#include "eapol.h"

/* some constants */

#define REFRESH_RATE 100000  /* default delay in us between updates */
#define DEFAULT_HOPFREQ 250  /* default delay in ms between channel hopping */
#define DEFAULT_CWIDTH  20 /* 20 MHz channels by default */

#define NB_PWR  5       /* size of signal power ring buffer */
#define NB_PRB 10       /* size of probed ESSID ring buffer */

#define MAX_CARDS 8	/* maximum number of cards to capture from */

#define	STD_OPN		0x0001
#define	STD_WEP		0x0002
#define	STD_WPA		0x0004
#define	STD_WPA2	0x0008

#define STD_FIELD	(STD_OPN | STD_WEP | STD_WPA | STD_WPA2)

#define	ENC_WEP		0x0010
#define	ENC_TKIP	0x0020
#define	ENC_WRAP	0x0040
#define	ENC_CCMP	0x0080
#define ENC_WEP40	0x1000
#define	ENC_WEP104	0x0100

#define ENC_FIELD	(ENC_WEP | ENC_TKIP | ENC_WRAP | ENC_CCMP | ENC_WEP40 | ENC_WEP104)

#define	AUTH_OPN	0x0200
#define	AUTH_PSK	0x0400
#define	AUTH_MGT	0x0800

#define AUTH_FIELD	(AUTH_OPN | AUTH_PSK | AUTH_MGT)

#define STD_QOS         0x2000

#define	QLT_TIME	5
#define	QLT_COUNT	25

#define SORT_BY_NOTHING 0
#define SORT_BY_BSSID	1
#define SORT_BY_POWER	2
#define SORT_BY_BEACON	3
#define SORT_BY_DATA	4
#define SORT_BY_PRATE	5
#define SORT_BY_CHAN	6
#define	SORT_BY_MBIT	7
#define SORT_BY_ENC	8
#define SORT_BY_CIPHER	9
#define SORT_BY_AUTH	10
#define SORT_BY_ESSID	11
#define MAX_SORT	11

#define TEXT_RESET	0
#define TEXT_BRIGHT 	1
#define TEXT_DIM	2
#define TEXT_UNDERLINE 	3
#define TEXT_BLINK	4
#define TEXT_REVERSE	7
#define TEXT_HIDDEN	8

#define TEXT_MAX_STYLE	8

#define TEXT_BLACK 	0
#define TEXT_RED	1
#define TEXT_GREEN	2
#define TEXT_YELLOW	3
#define TEXT_BLUE	4
#define TEXT_MAGENTA	5
#define TEXT_CYAN	6
#define	TEXT_WHITE	7

#define TEXT_MAX_COLOR	7

#define RATES           \
    "\x01\x04\x02\x04\x0B\x16\x32\x08\x0C\x12\x18\x24\x30\x48\x60\x6C"

#define PROBE_REQ       \
    "\x40\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xCC\xCC\xCC\xCC\xCC\xCC"  \
    "\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00"

//milliseconds to store last packets
#define BUFFER_TIME 3000

extern char * getVersion(char * progname, int maj, int min, int submin, int svnrev, int beta, int rc);
extern unsigned char * getmac(char * macAddress, int strict, unsigned char * mac);
extern int get_ram_size(void);

#define PCAP_ROLLOVER_TIME 5 * 60
#define JBLF_MAX_RECORD_COUNT 5000

#define AIRODUMP_NG_CSV_EXT "csv"
#define AIRODUMP_NG_GPS_EXT "gps"
#define AIRODUMP_NG_CAP_EXT "cap"
#define AIRODUMP_NG_PCAP_EXT "pcap"
#define JAIRODUMP_NG_JBLF_EXT "jblf"
#define JAIRODUMP_NG_TJBLF_EXT "tjblf" //temporary JBLF file, used while writing the output. Extension is changed to JAIRODUMP_NG_JBLF_EXT on log rollover

#define NB_EXTENSIONS 6

const unsigned char llcnull[4] = {0, 0, 0, 0};
char *f_ext[NB_EXTENSIONS] = { AIRODUMP_NG_CSV_EXT, AIRODUMP_NG_GPS_EXT, AIRODUMP_NG_CAP_EXT, AIRODUMP_NG_PCAP_EXT, JAIRODUMP_NG_JBLF_EXT, JAIRODUMP_NG_TJBLF_EXT };

extern const unsigned long int crc_tbl[256];
extern const unsigned char crc_chop_tbl[256][4];

static unsigned char ZERO[32] =
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00"
"\x00\x00\x00\x00\x00\x00\x00\x00";

#define OUI_PATH0 "/etc/aircrack-ng/airodump-ng-oui.txt"
#define OUI_PATH1 "/usr/local/etc/aircrack-ng/airodump-ng-oui.txt"
#define OUI_PATH2 "/usr/share/aircrack-ng/airodump-ng-oui.txt"
#define OUI_PATH3 "/usr/share/misc/oui.txt"
#define MIN_RAM_SIZE_LOAD_OUI_RAM 32768

int read_pkts=0;

int abg_chans [] =
{
    1, 7, 13, 2, 8, 3, 14, 9, 4, 10, 5, 11, 6, 12,
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108,
    112, 116, 120, 124, 128, 132, 136, 140, 149,
    153, 157, 161, 184, 188, 192, 196, 200, 204,
    208, 212, 216,0
};

int bg_chans  [] =
{
    1, 7, 13, 2, 8, 3, 14, 9, 4, 10, 5, 11, 6, 12, 0
};

int a_chans   [] =
{
    36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108,
    112, 116, 120, 124, 128, 132, 136, 140, 149,
    153, 157, 161, 184, 188, 192, 196, 200, 204,
    208, 212, 216,0
};

int *frequencies;

/* linked list of received packets for the last few seconds */
struct pkt_buf
{
    struct pkt_buf  *next;      /* next packet in list */
    unsigned char   *packet;    /* packet */
    unsigned short  length;     /* packet length */
    struct timeval  ctime;      /* capture time */
};

/* linked list of detected access points */
struct AP_info
{
    struct AP_info *prev;     /* prev. AP in list         */
    struct AP_info *next;     /* next  AP in list         */

    time_t tinit, tlast;      /* first and last time seen */

    int channel;              /* AP radio channel         */
    int max_speed;            /* AP maximum speed in Mb/s */
    int avg_power;            /* averaged signal power    */
    int best_power;           /* best signal power    */
    int power_index;          /* index in power ring buf. */
    int power_lvl[NB_PWR];    /* signal power ring buffer */
    int preamble;             /* 0 = long, 1 = short      */
    int security;             /* ENC_*, AUTH_*, STD_*     */
    int beacon_logged;        /* We need 1 beacon per AP  */
    int dict_started;         /* 1 if dict attack started */
    int ssid_length;          /* length of ssid           */
    float gps_loc_min[5];     /* min gps coordinates      */
    float gps_loc_max[5];     /* max gps coordinates      */
    float gps_loc_best[5];    /* best gps coordinates     */


    unsigned long nb_bcn;     /* total number of beacons  */
    unsigned long nb_pkt;     /* total number of packets  */
    unsigned long nb_data;    /* number of  data packets  */
    unsigned long nb_data_old;/* number of data packets/sec*/
    int nb_dataps;  /* number of data packets/sec*/
    struct timeval tv;        /* time for data per second */

    unsigned char bssid[6];   /* the access point's MAC   */
    unsigned char essid[MAX_IE_ELEMENT_SIZE];
                              /* ascii network identifier */
    unsigned long long timestamp;
    						  /* Timestamp to calculate uptime   */

    unsigned char lanip[4];   /* last detected ip address */
                              /* if non-encrypted network */

    unsigned char **uiv_root; /* unique iv root structure */
                              /* if wep-encrypted network */

    int    rx_quality;        /* percent of captured beacons */
    int    fcapt;             /* amount of captured frames   */
    int    fmiss;             /* amount of missed frames     */
    unsigned int    last_seq; /* last sequence number        */
    struct timeval ftimef;    /* time of first frame         */
    struct timeval ftimel;    /* time of last frame          */
    struct timeval ftimer;    /* time of restart             */

    char *key;		      /* if wep-key found by dict */

    char decloak_detect;      /* run decloak detection? */
    struct pkt_buf *packets;  /* list of captured packets (last few seconds) */
    char is_decloak;          /* detected decloak */

	// This feature eats 48Mb per AP
	int EAP_detected;
    unsigned char *data_root; /* first 2 bytes of data if */
    						  /* WEP network; used for    */
    						  /* detecting WEP cloak	  */
    						  /* + one byte to indicate   */
    						  /* (in)existence of the IV  */
					  
    int marked;
    int marked_color;
};

/* linked list of detected clients */

struct ST_info
{
    struct ST_info *prev;    /* the prev client in list   */
    struct ST_info *next;    /* the next client in list   */
    struct AP_info *base;    /* AP this client belongs to */
    time_t tinit, tlast;     /* first and last time seen  */
    unsigned long nb_pkt;    /* total number of packets   */
    unsigned char stmac[6];  /* the client's MAC address  */
    int probe_index;         /* probed ESSIDs ring index  */
    char probes[NB_PRB][MAX_IE_ELEMENT_SIZE];
                             /* probed ESSIDs ring buffer */
    int ssid_length[NB_PRB]; /* ssid lengths ring buffer  */
    int ssid_jblf_needs_log[NB_PRB]; /* does the ssid need to be jblf logged */
    int power;               /* last signal power         */
    int rate_to;             /* last bitrate to station   */
    int rate_from;           /* last bitrate from station */
    struct timeval ftimer;   /* time of restart           */
    int missed;              /* number of missed packets  */
    unsigned int lastseq;    /* last seen sequence number */
    struct WPA_hdsk wpa;     /* WPA handshake data        */
    int qos_to_ds;           /* does it use 802.11e to ds */
    int qos_fr_ds;           /* does it receive 802.11e   */
};

/* linked list of detected macs through ack, cts or rts frames */

struct NA_info
{
    struct NA_info *prev;    /* the prev client in list   */
    struct NA_info *next;    /* the next client in list   */
    time_t tinit, tlast;     /* first and last time seen  */
    unsigned char namac[6];  /* the stations MAC address  */
    int power;               /* last signal power         */
    int channel;             /* captured on channel       */
    int ack;                 /* number of ACK frames      */
    int ack_old;             /* old number of ACK frames  */
    int ackps;               /* number of ACK frames/s    */
    int cts;                 /* number of CTS frames      */
    int rts_r;               /* number of RTS frames (rx) */
    int rts_t;               /* number of RTS frames (tx) */
    int other;               /* number of other frames    */
    struct timeval tv;       /* time for ack per second   */
};
/* bunch of global stuff */

struct globals
{
    struct AP_info *ap_1st, *ap_end;
    struct ST_info *st_1st, *st_end;
    struct NA_info *na_1st, *na_end;
    
    unsigned char prev_bssid[6];
    unsigned char f_bssid[6];
    unsigned char f_netmask[6];
    char **f_essid;
    int f_essid_count;
#ifdef HAVE_PCRE
    pcre *f_essid_regex;
#endif
    char *dump_prefix;
    char *keyout;
    char *f_cap_name;
    char *f_jblf_name;

    int f_index;            /* outfiles index       */
    FILE *f_txt;            /* output csv file      */
    FILE *f_gps;            /* output gps file      */
    FILE *f_cap;            /* output cap file      */
    FILE *f_jblf;           /* output jblf file     */
    FILE *f_debug_log;      /* output errors */
    FILE *f_xor;            /* output prga file     */

    char * batt;            /* Battery string       */
    int channel[MAX_CARDS];           /* current channel #    */
    int frequency[MAX_CARDS];           /* current frequency #    */
    int ch_pipe[2];         /* current channel pipe */
    int cd_pipe[2];	    /* current card pipe    */
    int gc_pipe[2];         /* gps coordinates pipe */
    float gps_loc[5];       /* gps coordinates      */
    int save_gps;           /* keep gps file flag   */
    int usegpsd;            /* do we use GPSd?      */
    int *channels;
//     int *frequencies;
    int singlechan;         /* channel hopping set 1*/
    int singlefreq;         /* frequency hopping: 1 */
    int chswitch;	    /* switching method     */
    int f_encrypt;          /* encryption filter    */
    int update_s;	    /* update delay in sec  */

    int is_wlanng[MAX_CARDS];          /* set if wlan-ng       */
    int is_orinoco[MAX_CARDS];         /* set if orinoco       */
    int is_madwifing[MAX_CARDS];       /* set if madwifi-ng    */
    int is_zd1211rw[MAX_CARDS];       /* set if zd1211rw    */
    volatile int do_exit;            /* interrupt flag       */
    struct winsize ws;      /* console window size  */

    char * elapsed_time;	/* capture time			*/

    int one_beacon;         /* Record only 1 beacon?*/

    unsigned char sharedkey[3][4096]; /* array for 3 packets with a size of \
                               up to 4096Byte */
    time_t sk_start;
    char *prefix;
    int sk_len;
    int sk_len2;

    int * own_channels;	    /* custom channel list  */
    int * own_frequencies;	    /* custom frequency list  */

    int record_data;		/* do we record data?   */
    int asso_client;        /* only show associated clients */

    char * iwpriv;
    char * iwconfig;
    char * wlanctlng;
    char * wl;

    unsigned char wpa_bssid[6];   /* the wpa handshake bssid   */
    char message[512];
    char decloak;

    char is_berlin;           /* is the switch --berlin set? */
    int numaps;               /* number of APs on the current list */
    int maxnumaps;            /* maximum nubers of APs on the list */
    int maxaps;               /* number of all APs found */
    int berlin;               /* number of seconds it takes in berlin to fill the whole screen with APs*/
    /*
     * The name for this option may look quite strange, here is the story behind it:
     * During the CCC2007, 10 august 2007, we (hirte, Mister_X) went to visit Berlin
     * and couldn't resist to turn on airodump-ng to see how much access point we can
     * get during the trip from Finowfurt to Berlin. When we were in Berlin, the number
     * of AP increase really fast, so fast that it couldn't fit in a screen, even rotated;
     * the list was really huge (we have a picture of that). The 2 minutes timeout
     * (if the last packet seen is higher than 2 minutes, the AP isn't shown anymore)
     * wasn't enough, so we decided to create a new option to change that timeout.
     * We implemented this option in the highest tower (TV Tower) of Berlin, eating an ice.
     */

    int show_ap;
    int show_sta;
    int show_ack;
    int hide_known;

    int hopfreq;

    char*   s_iface;        /* source interface to read from */
    struct pcap_file_header pfh_in;
    int detect_anomaly;     /* Detect WIPS protecting WEP in action */

    char *freqstring;
    int freqoption;
    int chanoption;
    int active_scan_sim;    /* simulates an active scan, sending probe requests */

    time_t dump_cap_start;
    int roll_cap_files;
    int roll_cap_files_time;

    int jblf_output_cnt;
    int jblf_output_max_cnt;
    char * jblf_empty_tag_flush;

    int output_debug_log;
    int output_format_pcap;
    int output_format_jblf;
    int output_format_csv;
    pthread_t input_tid;
    int sort_by;
    int sort_inv;
    int start_print_ap;
    int start_print_sta;
    int selected_ap;
    int selected_sta;
    int selection_ap;
    int selection_sta;
    int mark_cur_ap;
    int num_cards;
    int skip_columns;
    int do_pause;
    int do_sort_always;

    int jblf_gps_data_available;
    
    pthread_mutex_t mx_print;			 /* lock write access to ap LL   */
    pthread_mutex_t mx_sort;			 /* lock write access to ap LL   */
    
    unsigned char selected_bssid[6];	/* bssid that is selected */

    int ignore_negative_one;
    u_int maxsize_essid_seen;
    int show_uptime;
}
G;

/* JBLF (Joe's Binary Log File) defines */
#define JBLF_VERSION_MAJOR      1
#define JBLF_VERSION_MINOR      0

#define JBLF_PKT_TYPE_IP        0x00
#define JBLF_PKT_TYPE_GPS       0x01

#define JBLF_TAG_FILTER_SIZE    0x8000

#define JBLF_TAG_EMPTY          0x0000
#define JBLF_TAG_RX_INFO        0x0001
#define JBLF_TAG_ETHER_TYPE     0x0002
#define JBLF_TAG_LOCATION       0x0003
#define JBLF_TAG_SSID_NAME      0x0004
#define JBLF_TAG_DNS_NAME       0x0005
#define JBLF_TAG_URL            0x0006
#define JBLF_TAG_USER_AGENT     0x0007
#define JBLF_TAG_UDP_PKT_SIZE   0x0008
#define JBLF_TAG_TCP_PKT_SIZE   0x0009

#define JBLF_GPS_INTERVAL       60 * 3 /* 3-second max time check */

#define JBLF_EMPTY_TAG_FLUSH    "\xFF\xAA\xFF\xAA\xEE\xBB\xEE\xBB"

/* Misc network protocol structures */
struct dns_hdr
{
    unsigned short id; // identification number
 
    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag
 
    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available
 
    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
};

//Constant sized fields of query structure
struct dns_question
{
    unsigned short qtype;
    unsigned short qclass;
};
 
//Constant sized fields of the resource record structure
#pragma pack(push, 1)
struct dns_r_data
{
    unsigned short type;
    unsigned short _class;
    unsigned int ttl;
    unsigned short data_len;
};
#pragma pack(pop)
 
//Pointers to resource record contents
struct dns_res_record
{
    unsigned char *name;
    struct R_DATA *resource;
    unsigned char *rdata;
};
 
//Structure of a Query
typedef struct
{
    unsigned char *name;
    struct dns_question *ques;
} dns_query;

#endif
