#include <stddef.h>
#include <errno.h>
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#ifndef __APPLE__
    #include <endian.h>
#else
    #include <libkern/OSByteOrder.h>
    #define bswap_16 OSSwapInt16
    #define bswap_32 OSSwapInt32
    #define bswap_64 OSSwapInt64
    #include <machine/endian.h>
    #define le16toh(x) OSSwapLittleToHostInt16(x)
    #define le32toh(x) OSSwapLittleToHostInt32(x)
#endif

#define le16_to_cpu		le16toh
#define le32_to_cpu		le32toh
#define get_unaligned(p)					\
({								\
	struct packed_dummy_struct {				\
		typeof(*(p)) __val;				\
	} __attribute__((packed)) *__ptr = (void *) (p);	\
								\
	__ptr->__val;						\
})
#define get_unaligned_le16(p)	le16_to_cpu(get_unaligned((uint16_t *)(p)))
#define get_unaligned_le32(p)	le32_to_cpu(get_unaligned((uint32_t *)(p)))
