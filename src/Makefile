AC_ROOT		= ..
include $(AC_ROOT)/common.mak

TEST_DIR	= $(AC_ROOT)/test

CFLAGS		+= -Iinclude

iCC             = $(shell find /opt/intel/cc/*/bin/icc)
iCFLAGS         = -w -mcpu=pentiumpro -march=pentiumpro $(COMMON_CFLAGS)
iOPTFLAGS       = -O3 -ip -ipo -D_FILE_OFFSET_BITS=64
PROF_DIR	= $(PWD)/prof

BINFILES        = aircrack-ng$(EXE) ivstools$(EXE) kstats$(EXE) makeivs-ng$(EXE) \
		  wpaclean$(EXE)

LIBPCRE		=
ifeq ($(PCRE), true)
	LIBPCRE	= $(shell pcre-config --libs)
endif

ifneq ($(OSNAME), cygwin) #There is yet no libpcap support for windows, so we skip the crawler
	HAVE_PCAP	= $(shell ld -lpcap 2> /dev/null && echo yes)
	ifeq ($(HAVE_PCAP), yes) #cannot link with -lpcap, skip crawler
		BINFILES	+= besside-ng-crawler$(EXE)
	endif
endif

ifeq ($(subst TRUE,true,$(filter TRUE true,$(sqlite) $(SQLITE))),true)
	BINFILES	+= airolib-ng$(EXE)
endif


SBINFILES       = airodump-ng$(EXE) airserv-ng$(EXE) \
		  airtun-ng$(EXE) besside-ng$(EXE) jairodump-ng$(EXE) jupload$(EXE)
		  
OPTFILES	= aircrack-ng-opt-prof_gen aircrack-ng-opt \
		  aircrack-ng-opt-prof prof/*


ifeq ($(subst TRUE,true,$(filter TRUE true,$(unstable) $(UNSTABLE))),true)
	BINFILES	+= buddy-ng$(EXE)
endif


SRC_PTW		= aircrack-ptw-lib.c
SRC_AC		= aircrack-ng.c crypto.c common.c $(SRC_PTW)
OBJS_PTW	= aircrack-ptw-lib.o
OBJS_AC		= aircrack-ng.o crypto.o common.o uniqueiv.o $(OBJS_PTW)
ASM_AC		= sha1-sse2.S

OBJS_ADU	= airodump-ng.o common.o crypto.o uniqueiv.o osdep/radiotap/radiotap.o
OBJS_JDU	= jairodump-ng.o common.o crypto.o uniqueiv.o osdep/radiotap/radiotap.o
ifneq ($(OSNAME), Linux)
	OBJS_ADU	+= osdep/common.o
	OBJS_JDU    += osdep/common.o
endif
OBJS_AT		= airtun-ng.o common.o crypto.o osdep/radiotap/radiotap.o
OBJS_IV		= ivstools.o common.o crypto.o uniqueiv.o
OBJS_AS		= airserv-ng.o common.o osdep/radiotap/radiotap.o
OBJS_BS		= besside-ng.o crypto.o common.o osdep/radiotap/radiotap.o $(OBJS_PTW)
OBJS_BC		= besside-ng-crawler.o
OBJS_AL		= airolib-ng.o crypto.o common.o
OBJS_BUDDY	= buddy-ng.o common.o
OBJS_MI		= makeivs-ng.o common.o uniqueiv.o
OBJS_WC		= wpaclean.o osdep/radiotap/radiotap.o
OBJS_JU     = jupload.o common.o

OSD		= osdep
LIBS		:= -L$(OSD) -l$(OSD) $(LIBS)
ifeq ($(OSNAME), cygwin)
LIBS		+= -liphlpapi -lsetupapi -luuid
endif
LIBOSD		= $(OSD)/lib$(OSD).a

LIBSSL		= -lssl -lcrypto
ifeq ($(subst TRUE,true,$(filter TRUE true,$(gcrypt) $(GCRYPT))),true)
	LIBSSL		= -lgcrypt $(LDFLAGS)
	CFLAGS 		+= -DUSE_GCRYPT
	OBJS_AC		+= sha1-git.o
	OBJS_IV		+= sha1-git.o
	OBJS_ADU	+= sha1-git.o
	OBJS_JDU	+= sha1-git.o
	OBJS_AT		+= sha1-git.o
	OBJS_AL		+= sha1-git.o
	OBJS_BS		+= sha1-git.o
else
	LIBSSL		= -lssl -lcrypto $(LDFLAGS)
endif


ifeq ($(subst TRUE,true,$(filter TRUE true,$(sqlite) $(SQLITE))),true)
	LIBSQL		= -L/usr/local/lib -lsqlite3
else
	LIBSQL		=
endif

all: userland $(SBINFILES)

userland: $(BINFILES)

$(LIBOSD):
	$(MAKE) -C $(OSD)

aircrack-ng-opt: $(SRC_AC)
	$(iCC) $(iCFLAGS) $(iOPTFLAGS) $(REVFLAGS) $(SRC_AC) $(ASM_AC) $(LIBSSL) \
	uniqueiv.o -o aircrack-ng-opt -lpthread $(LIBSQL)

aircrack-ng-opt-prof_gen: $(SRC_AC)
	mkdir -p prof
	$(iCC) $(iCFLAGS) $(iOPTFLAGS) $(REVFLAGS) -prof_genx -DDO_PGO_DUMP \
	-prof_dir$(PROF_DIR) $(SRC_AC) $(ASM_AC) $(LIBSSL) uniqueiv.o -o \
	aircrack-ng-opt-prof_gen -lpthread $(LIBSQL)

aircrack-ng-opt-prof_use: $(SRC_AC)
	$(iCC) $(iCFLAGS) $(iOPTFLAGS) $(REVFLAGS) -prof_use \
	-prof_dir$(PROF_DIR) $(SRC_AC) $(ASM_AC) $(LIBSSL) uniqueiv.o -o \
	aircrack-ng-opt-prof -lpthread $(LIBSQL)

aircrack-ng$(EXE): $(OBJS_AC)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS_AC) $(ASM_AC) -o $(@) -lpthread $(LIBSSL) $(LIBSQL)

airodump-ng$(EXE): $(OBJS_ADU) $(LIBOSD)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS_ADU) -o $(@) $(LIBS) $(LIBSSL) -lpthread $(LIBPCRE)

jairodump-ng$(EXE): $(OBJS_JDU) $(LIBOSD)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS_JDU) -o $(@) $(LIBS) $(LIBSSL) -lpthread $(LIBPCRE) -lcurl

jupload$(EXE): $(OBJS_JU) $(LIBOSD)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS_JU) -o $(@) $(LIBS) -lpthread $(LIBPCRE) -lcurl

airserv-ng$(EXE): $(OBJS_AS) $(LIBOSD)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS_AS) -o $(@) $(LIBS)

airtun-ng$(EXE): $(OBJS_AT) $(LIBOSD)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS_AT) -o $(@) $(LIBS) $(LIBSSL)

ivstools$(EXE): $(OBJS_IV)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS_IV) -o $(@) $(LIBSSL)

kstats$(EXE): kstats.o
	$(CC) $(CFLAGS) $(LDFLAGS) kstats.o -o $(@) $(LDFLAGS)

buddy-ng$(EXE): $(OBJS_BUDDY)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS_BUDDY) -o $(@) $(LDFLAGS)

besside-ng$(EXE): $(OBJS_BS) $(LIBOSD)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS_BS) -o $(@) $(LIBS) $(LIBSSL) -lz $(LIBPCRE)

besside-ng-crawler$(EXE): $(OBJS_BC)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS_BC) -o $(@) -lpcap

makeivs-ng$(EXE): $(OBJS_MI)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS_MI) -o $(@) $(LDFLAGS)

airolib-ng$(EXE): $(OBJS_AL)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS_AL) -o $(@) $(LIBSSL) -DHAVE_REGEXP $(LIBSQL)

wpaclean$(EXE): $(OBJS_WC) $(LIBOSD)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS_WC) -o $(@) $(LIBS)

strip: $(BINFILES) $(SBINFILES)
	strip $(BINFILES) $(SBINFILES)

clean:
	$(MAKE) -C $(OSD) clean
	-rm -f $(SBINFILES) $(BINFILES) $(OPTFILES) airolib-ng$(EXE) *.o buddy-ng$(EXE) a.out

distclean: clean

install: all
	$(MAKE) -C $(OSD) install
	install -d $(DESTDIR)$(bindir)
	install -m 755 $(BINFILES) $(DESTDIR)$(bindir)
	install -d $(DESTDIR)$(sbindir)
	install -m 755 $(SBINFILES) $(DESTDIR)$(sbindir)

uninstall:
	$(MAKE) -C $(OSD) uninstall
	-rm -f $(DESTDIR)$(bindir)/aircrack-ng$(EXE)
	-rm -f $(DESTDIR)$(bindir)/airdecap-ng$(EXE)
	-rm -f $(DESTDIR)$(bindir)/packetforge-ng$(EXE)
	-rm -f $(DESTDIR)$(bindir)/airolib-ng$(EXE)
	-rm -f $(DESTDIR)$(bindir)/ivstools$(EXE)
	-rm -f $(DESTDIR)$(bindir)/kstats$(EXE)
	-rm -f $(DESTDIR)$(bindir)/buddy-ng$(EXE)
	-rm -f $(DESTDIR)$(sbindir)/airodump-ng$(EXE)
	-rm -f $(DESTDIR)$(sbindir)/jairodump-ng$(EXE)
	-rm -f $(DESTDIR)$(sbindir)/airserv-ng$(EXE)
	-rm -f $(DESTDIR)$(sbindir)/airtun-ng$(EXE)
	-rm -f $(DESTDIR)$(sbindir)/aireplay-ng$(EXE)
	-rm -f $(DESTDIR)$(sbindir)/wesside-ng$(EXE)
	-rm -f $(DESTDIR)$(sbindir)/easside-ng$(EXE)
	-rm -f $(DESTDIR)$(sbindir)/besside-ng$(EXE)
	-rm -f $(DESTDIR)$(bindir)/besside-ng-crawler$(EXE)
	-rm -f $(DESTDIR)$(bindir)/wpaclean$(EXE)
	-rm -f $(DESTDIR)$(sbindir)/airbase-ng$(EXE)
	-rm -f $(DESTDIR)$(bindir)/makeivs-ng$(EXE)
	-rm -f $(DESTDIR)$(bindir)/airdecloak-ng$(EXE)
	-rm -f $(DESTDIR)$(sbindir)/tkiptun-ng$(EXE)
	-rm -f $(DESTDIR)$(sbindir)/jupload$(EXE)
	-rm -rf $(DESTDIR)$(etcdir)

check: all
	./aircrack-ng$(EXE) -w $(TEST_DIR)/password.lst -a 2 -e Harkonen -q $(TEST_DIR)/wpa2.eapol.cap | grep 'KEY FOUND! \[ 12345678 \]' 
	./aircrack-ng$(EXE) -w $(TEST_DIR)/password.lst -a 2 -e test -q $(TEST_DIR)/wpa.cap | grep 'KEY FOUND! \[ biscotte \]'
	./aircrack-ng$(EXE) -w $(TEST_DIR)/password.lst -a 2 -e linksys -q $(TEST_DIR)/wpa2-psk-linksys.cap | grep 'KEY FOUND! \[ dictionary \]'
	./aircrack-ng$(EXE) -w $(TEST_DIR)/password.lst -a 2 -e linksys -q $(TEST_DIR)/wpa-psk-linksys.cap | grep 'KEY FOUND! \[ dictionary \]'
ifeq ($(subst TRUE,true,$(filter TRUE true,$(sqlite) $(SQLITE))),true)
	$(TEST_DIR)/test-airolib-sqlite.sh $(CURDIR)
endif
