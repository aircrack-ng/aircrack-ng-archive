 /*
  *  Copyright (c) 2009, Kyle Fuller <inbox@kylefuller.co.uk>, based upon 
  *  freebsd.c by Andrea Bittau <a.bittau@cs.ucl.ac.uk>
  *
  *  OS dependent API for Darwin.
  *
  *  This program is free software; you can redistribute it and/or modify
  *  it under the terms of the GNU General Public License as published by
  *  the Free Software Foundation; either version 2 of the License, or
  *  (at your option) any later version.
  *
  *  This program is distributed in the hope that it will be useful,
  *  but WITHOUT ANY WARRANTY; without even the implied warranty of
  *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  *  GNU General Public License for more details.
  *
  *  You should have received a copy of the GNU General Public License
  *  along with this program; if not, write to the Free Software
  *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
  */
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <net/bpf.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_media.h>
   #define IFM_IEEE80211_HOSTAP    0x00000200      /* Operate in Host AP mode */
   #define IFM_IEEE80211_IBSS      0x00000400      /* Operate in IBSS mode */
   #define IFM_IEEE80211_WDS       0x00000800      /* Operate in WDS mode */
   #define IFM_IEEE80211_TURBO     0x00001000      /* Operate in turbo mode */
   #define IFM_IEEE80211_MONITOR   0x00002000      /* Operate in monitor mode */
   #define IFM_IEEE80211_MBSS      0x00004000      /* Operate in MBSS mode */
#include <sys/ioctl.h>
#include <net/if_dl.h>
// #include <net80211/ieee80211_ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/uio.h>
#include <assert.h>
#include <ifaddrs.h>

#include "ieee802_11_radio.h"
#include "ieee802_11.h"
#define IEEE80211_CRC_LEN               4

#include "osdep.h"

struct priv_darwin {
  /* iface */
  int       pd_fd;

  /* rx */
  int       pd_nocrc;

  /* tx */
  unsigned char     pd_buf[4096];
  unsigned char     *pd_next;
  int       pd_totlen;
        // struct ieee80211_bpf_params pf_txparams;

  /* setchan */
  int       pd_s;
  struct ifreq      pd_ifr;
  // struct ieee80211req   pf_ireq;
        int                             pd_chan;
};

/* from ifconfig */
static __inline int
mapgsm(u_int freq, u_int flags)
{
        freq *= 10;
        if (flags & IEEE80211_CHAN_QUARTER)
                freq += 5;
        else if (flags & IEEE80211_CHAN_HALF)
                freq += 10;
        else
                freq += 20;
        /* NB: there is no 907/20 wide but leave room */
        return (freq - 906*10) / 5;
}

static __inline int
mappsb(u_int freq)
{
        return 37 + ((freq * 10) + ((freq % 5) == 2 ? 5 : 0) - 49400) / 5;
}

/*
 * Convert MHz frequency to IEEE channel number.
 */
static u_int
ieee80211_mhz2ieee(u_int freq, u_int flags)
{
        if ((flags & IEEE80211_CHAN_GSM) || (907 <= freq && freq <= 922))
                return mapgsm(freq, flags);
        if (freq == 2484)
                return 14;
        if (freq < 2484)
                return (freq - 2407) / 5;
        if (freq < 5000) {
                if (flags & (IEEE80211_CHAN_HALF|IEEE80211_CHAN_QUARTER))
                        return mappsb(freq);
                else if (freq > 4900)
                        return (freq - 4000) / 5;
                else
                        return 15 + ((freq - 2512) / 20);
        }
        return (freq - 5000) / 5;
}
/* end of ifconfig */

static void get_radiotap_info(struct priv_darwin *pd,
            struct ieee80211_radiotap_header *rth, int *plen,
            struct rx_info *ri)
{
        uint32_t present;
  uint8_t rflags = 0;
  int i;
  unsigned char *body = (unsigned char*) (rth+1);
  int dbm_power = 0, db_power = 0;

  /* reset control info */
  if (ri)
    memset(ri, 0, sizeof(*ri));

        /* get info */
  present = le32toh(rth->it_present);
  for (i = IEEE80211_RADIOTAP_TSFT; i <= IEEE80211_RADIOTAP_EXT; i++) {
    if (!(present & (1 << i)))
      continue;

    switch (i) {
    case IEEE80211_RADIOTAP_TSFT:
      body += sizeof(uint64_t);
      break;

    case IEEE80211_RADIOTAP_FLAGS:
      rflags = *((uint8_t*)body);
      /* fall through */
    case IEEE80211_RADIOTAP_RATE:
      body += sizeof(uint8_t);
      break;

    case IEEE80211_RADIOTAP_CHANNEL:
      if (ri) {
        uint16_t *p = (uint16_t*) body;
        int c = ieee80211_mhz2ieee(*p, *(p+1));

        ri->ri_channel = c;
      }
      body += sizeof(uint16_t)*2;
      break;

    case IEEE80211_RADIOTAP_FHSS:
      body += sizeof(uint16_t);
      break;

    case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
      dbm_power = *body++;
      break;

    case IEEE80211_RADIOTAP_DBM_ANTNOISE:
      dbm_power -= *body++;
      break;

    case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
      db_power = *body++;
      break;

    case IEEE80211_RADIOTAP_DB_ANTNOISE:
      db_power -= *body++;
      break;

    default:
      i = IEEE80211_RADIOTAP_EXT+1;
      break;
    }
  }

  /* set power */
  if (ri) {
    if (dbm_power)
      ri->ri_power = dbm_power;
    else
      ri->ri_power = db_power;
  }

        /* XXX cache; drivers won't change this per-packet */
        /* check if FCS/CRC is included in packet */
        if (pd->pd_nocrc || (rflags & IEEE80211_RADIOTAP_F_FCS)) {
                *plen -= IEEE80211_CRC_LEN;
                pd->pd_nocrc = 1;
        }
}

static unsigned char *get_80211(struct priv_darwin *pd, int *plen,
        struct rx_info *ri)
{
        struct bpf_hdr *bpfh;
        struct ieee80211_radiotap_header *rth;
        void *ptr;
        unsigned char **data;
  int *totlen;

  data = &pd->pd_next;
  totlen = &pd->pd_totlen;
  assert(*totlen);

        /* bpf hdr */
        bpfh = (struct bpf_hdr*) (*data);
        assert(bpfh->bh_caplen == bpfh->bh_datalen); /* XXX */
        *totlen -= bpfh->bh_hdrlen;

        /* check if more packets */
        if ((int)bpfh->bh_caplen < *totlen) {
    int tot = bpfh->bh_hdrlen + bpfh->bh_caplen;
    int offset = BPF_WORDALIGN(tot);

                *data = (unsigned char*)bpfh + offset;
    *totlen -= offset - tot; /* take into account align bytes */
  } else if ((int)bpfh->bh_caplen > *totlen)
    abort();

        *plen = bpfh->bh_caplen;
  *totlen -= bpfh->bh_caplen;
  assert(*totlen >= 0);

        /* radiotap */
        rth = (struct ieee80211_radiotap_header*)
              ((char*)bpfh + bpfh->bh_hdrlen);
  get_radiotap_info(pd, rth, plen, ri);
        *plen -= rth->it_len;
  assert(*plen > 0);

        /* data */
  ptr = (char*)rth + rth->it_len;

        return ptr;
}

static int darwin_get_channel(struct wif *wi)
{
  struct priv_darwin *pd = wi_priv(wi);
  char buf[32];
  FILE *fp = NULL;

  fp = popen("/System/Library/PrivateFrameworks/Apple80211.framework/Resources/airport -c", "r");

  if (fread(buf, sizeof(char), sizeof(buf), fp) <= 9)
    return -1;

  pd->pd_chan = atoi(buf+sizeof("channel:"));
  pclose(fp);
  fp = NULL;
  return pd->pd_chan;
}

static int darwin_read(struct wif *wi, unsigned char *h80211, int len,
         struct rx_info *ri)
{
  struct priv_darwin *pd = wi_priv(wi);
  unsigned char *wh;
  int plen;

  assert(len > 0);

  /* need to read more */
  if (pd->pd_totlen == 0) {
    pd->pd_totlen = read(pd->pd_fd, pd->pd_buf, sizeof(pd->pd_buf));
    if (pd->pd_totlen == -1) {
      pd->pd_totlen = 0;
      return -1;
    }
    pd->pd_next = pd->pd_buf;
  }

  /* read 802.11 packet */
  wh = get_80211(pd, &plen, ri);
  if (plen > len)
    plen = len;
  assert(plen > 0);
  memcpy(h80211, wh, plen);

        if(ri && !ri->ri_channel)
            ri->ri_channel = wi_get_channel(wi);

  return plen;
}

static int darwin_write(struct wif *wi, unsigned char *h80211, int len,
          struct tx_info *ti)
{
  struct priv_darwin *pd = wi_priv(wi);
  int rc;

  /* XXX make use of ti */
  if (ti) {}

  rc = write(pd->pd_fd, h80211, len);
  if (rc == -1)
    return rc;

  return 0;
}

static int darwin_set_channel(struct wif *wi, int chan)
{
  // There is an API to change the channel since OS X 10.7,Unfortunately I don't want to use it.
  pid_t pid = fork();
  if (!pid) {
    char chan_arg[32];
    sprintf(chan_arg, "-c%d", chan);
    char* argv[] = {"/System/Library/PrivateFrameworks/Apple80211.framework/Resources/airport", chan_arg, NULL};
    execve("/System/Library/PrivateFrameworks/Apple80211.framework/Resources/airport", argv, NULL);
  }
  int status;
  waitpid(pid,&status,0);

  struct priv_darwin *pd = wi_priv(wi);

  if( status != 0 /*|| darwin_get_channel(wi) != chan*/)
    return -1;

  pd->pd_chan = chan;
  return 0;
}

static void do_free(struct wif *wi)
{
  assert(wi->wi_priv);
  free(wi->wi_priv);
  wi->wi_priv = 0;
  free(wi);
}

static void darwin_close(struct wif *wi)
{
  struct priv_darwin *pd = wi_priv(wi);

  close(pd->pd_fd);
  close(pd->pd_s);
  do_free(wi);
}

static int do_darwin_open(struct wif *wi, char *iface)
{
        int i;
        char buf[64];
        int fd = -1;
        struct ifreq ifr;
        unsigned int dlt = DLT_IEEE802_11_RADIO;
        int s;
        unsigned int flags;
        struct ifmediareq ifmr;
        int *mwords;
  struct priv_darwin *pd = wi_priv(wi);

  /* basic sanity check */
  if (strlen(iface) >= sizeof(ifr.ifr_name))
    return -1;

        /* open wifi */
        s = socket(PF_INET, SOCK_DGRAM, 0);
        if (s == -1)
    return -1;
  pd->pd_s = s;

        /* set iface up and promisc */
        memset(&ifr, 0, sizeof(ifr));
        strcpy(ifr.ifr_name, iface);
        if (ioctl(s, SIOCGIFFLAGS, &ifr) == -1)
    goto close_sock;

        flags = (ifr.ifr_flags & 0xffff);
        flags |= IFF_UP | IFF_PROMISC;
        memset(&ifr, 0, sizeof(ifr));
        strcpy(ifr.ifr_name, iface);
        ifr.ifr_flags = flags & 0xffff;
        // ifr.ifr_flagshigh = flags >> 16;
        if (ioctl(s, SIOCSIFFLAGS, &ifr) == -1)
    goto close_sock;

  /* monitor mode */
        memset(&ifmr, 0, sizeof(ifmr));
        strcpy(ifmr.ifm_name, iface);
        if (ioctl(s, SIOCGIFMEDIA, &ifmr) == -1)
    goto close_sock;

        assert(ifmr.ifm_count != 0);

        mwords = (int *)malloc(ifmr.ifm_count * sizeof(int));
        if (!mwords)
    goto close_sock;
        ifmr.ifm_ulist = mwords;
        if (ioctl(s, SIOCGIFMEDIA, &ifmr) == -1) {
    free(mwords);
    goto close_sock;
  }
        free(mwords);

        memset(&ifr, 0, sizeof(ifr));
        strcpy(ifr.ifr_name, iface);
        ifr.ifr_media = ifmr.ifm_current | IFM_IEEE80211_MONITOR;
        if (ioctl(s, SIOCSIFMEDIA, &ifr) == -1)
    goto close_sock;

  // /* setup ifreq for chan that may be used in future */
  // strcpy(pd->pf_ireq.i_name, iface);
  // pd->pf_ireq.i_type = IEEE80211_IOC_CHANNEL;

  // /* same for ifreq [mac addr] */
  // strcpy(pd->pd_ifr.ifr_name, iface);

        /* open bpf */
        for(i = 0; i < 256; i++) {
                sprintf(buf, "/dev/bpf%d", i);

                fd = open(buf, O_RDWR);
                if(fd < 0) {
                        if(errno != EBUSY)
        return -1;
                        continue;
                }
                else
                        break;
        }

        if(fd < 0)
    goto close_sock;

  strcpy(ifr.ifr_name, iface);

        if(ioctl(fd, BIOCSETIF, &ifr) < 0)
    goto close_bpf;

        if (ioctl(fd, BIOCSDLT, &dlt) < 0)
    goto close_bpf;

        dlt = 1;
        if (ioctl(fd, BIOCIMMEDIATE, &dlt) == -1)
    goto close_bpf;

  return fd;

close_sock:
  close(s);
  return -1;
close_bpf:
  close(fd);
  goto close_sock;
}

static int darwin_fd(struct wif *wi)
{
  struct priv_darwin *pd = wi_priv(wi);

  return pd->pd_fd;
}

static int darwin_get_mac(struct wif *wi, unsigned char *mac)
{
  struct ifaddrs *ifa, *p;
  char *name = wi_get_ifname(wi);
  int rc = -1;
  struct sockaddr_dl* sdp;

  if (getifaddrs(&ifa) == -1)
    return -1;

  p = ifa;
  while (p) {
    if (p->ifa_addr->sa_family == AF_LINK &&
        strcmp(name, p->ifa_name) == 0) {

          sdp = (struct sockaddr_dl*) p->ifa_addr;
      memcpy(mac, sdp->sdl_data + sdp->sdl_nlen, 6);
      rc = 0;
      break;
    }

    p = p->ifa_next;
  }
  freeifaddrs(ifa);

  return rc;
}

static int darwin_get_monitor(struct wif *wi)
{
  if (wi) {} /* XXX unused */

  /* XXX */
  return 0;
}

static int darwin_get_rate(struct wif *wi)
{
  if (wi) {} /* XXX unused */

  /* XXX */
  return 1000000;
}

static int darwin_set_rate(struct wif *wi, int rate)
{
  if (wi || rate) {} /* XXX unused */

  /* XXX */
  return 0;
}

static int darwin_set_mac(struct wif *wi, unsigned char *mac)
{
  struct priv_darwin *priv = wi_priv(wi);
  struct ifreq *ifr = &priv->pd_ifr;

  ifr->ifr_addr.sa_family = AF_LINK;
  ifr->ifr_addr.sa_len = 6;
  memcpy(ifr->ifr_addr.sa_data, mac, 6);

  return ioctl(priv->pd_s, SIOCSIFLLADDR, ifr);
}

static struct wif *darwin_open(char *iface)
{
  struct wif *wi;
  struct priv_darwin *pd;
  int fd;

  /* setup wi struct */
  wi = wi_alloc(sizeof(*pd));
  if (!wi)
    return NULL;
  wi->wi_read   = darwin_read;
  wi->wi_write    = darwin_write;
  wi->wi_set_channel  = darwin_set_channel;
  wi->wi_get_channel  = darwin_get_channel;
  wi->wi_close    = darwin_close;
  wi->wi_fd   = darwin_fd;
  wi->wi_get_mac    = darwin_get_mac;
  wi->wi_set_mac    = darwin_set_mac;
  wi->wi_get_rate   = darwin_get_rate;
  wi->wi_set_rate   = darwin_set_rate;
        wi->wi_get_monitor      = darwin_get_monitor;

  /* setup iface */
  fd = do_darwin_open(wi, iface);
  if (fd == -1) {
    do_free(wi);
    return NULL;
  }

  /* setup private state */
  pd = wi_priv(wi);
  pd->pd_fd = fd;
  //       pd->pf_txparams.ibp_vers = IEEE80211_BPF_VERSION;
  // pd->pf_txparams.ibp_len = sizeof(struct ieee80211_bpf_params) - 6;
  // pd->pf_txparams.ibp_rate1 = 2;         /* 1 MB/s XXX */
  // pd->pf_txparams.ibp_try1 = 1;          /* no retransmits */
  // pd->pf_txparams.ibp_flags = IEEE80211_BPF_NOACK;
  // pd->pf_txparams.ibp_power = 100;       /* nominal max */
  // pd->pf_txparams.ibp_pri = WME_AC_VO;   /* high priority */

  return wi;
}

struct wif *wi_open_osdep(char *iface)
{
  prinrf("wi_open_osdep\n");
  return darwin_open(iface);
}


int get_battery_state(void)
{
  pid_t pid = fork();
  if (!pid) {
    char* argv[] = {"pmset", "-g", "batt", NULL};
    execve("pmset", argv, NULL);
  }
  int status;
  waitpid(pid,&status,0);

	// errno = EOPNOTSUPP;
	// return -1;
}

int create_tap(void)
{
	errno = EOPNOTSUPP;
	return -1;
}
