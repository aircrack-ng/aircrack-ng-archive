/*
 * Based on John the Ripper and modified to integrate with aircrack
 *
 * 	John the Ripper copyright and license.
 *
 * John the Ripper password cracker,
 * Copyright (c) 1996-2013 by Solar Designer.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * As a special exception to the GNU General Public License terms,
 * permission is hereby granted to link the code of this program, with or
 * without modification, with any version of the OpenSSL library and/or any
 * version of unRAR, and to distribute such linked combinations.  You must
 * obey the GNU GPL in all respects for all of the code used other than
 * OpenSSL and unRAR.  If you modify this program, you may extend this
 * exception to your version of the program, but you are not obligated to
 * do so.  (In other words, you may release your derived work under pure
 * GNU GPL version 2 or later as published by the FSF.)
 *
 * (This exception from the GNU GPL is not required for the core tree of
 * John the Ripper, but arguably it is required for -jumbo.)
 *
 * 	Relaxed terms for certain components.
 *
 * In addition or alternatively to the license above, many components are
 * available to you under more relaxed terms (most commonly under cut-down
 * BSD license) as specified in the corresponding source files.
 *
 * For more information on John the Ripper licensing please visit:
 *
 * http://www.openwall.com/john/doc/LICENSE.shtml
 *
 * Minimalistic pseudo-instrinsics for width-agnostic x86 SIMD code.
 *
 * This software is Copyright (c) 2015 magnum,
 * Copyright (c) 2015 JimF,
 * Copyright (c) 2015 Lei Zhang,
 * and it is hereby released to the general public under the following terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * Synopsis:
 *
 * SSE2:     __m128i a = _mm_add_epi32(b, c);
 * AVX2:     __m256i a = _mm256_add_epi32(b, c);
 * AVX512:   __m512i a = _mm512_add_epi32(b, c);
 * -> Pseudo:  vtype a = vadd_epi32(b, c);
 *
 * SSE2:     __m128i a = _mm_load_si128(p);
 * AVX2:     __m256i a = _mm256_load_si256(p);
 * AVX512:   __m512i a = _mm512_load_si512(p);
 * -> Pseudo:  vtype a = vload(p);
 *
 * intrinsics are emulated where the target does not support them.
 */

#ifndef _SSE_PSEUDO_H
#define _SSE_PSEUDO_H

#include "arch.h"

#if SIMD_COEF_32

#include "aligned.h"
#include "stdint.h"
#include "jcommon.h" /* for is_aligned() */


/*************************** NEON (ARM) *******************************/
#ifdef __ARM_NEON__
#include <arm_neon.h>

typedef uint8x16_t vtype8;
typedef uint32x4_t vtype; /* the default one */
typedef uint64x2_t vtype64;

#define vadd_epi32              vaddq_u32
#define vadd_epi64(x, y)        (vtype)vaddq_u64((vtype64)(x), (vtype64)(y))
#define vand                    vandq_u32
#define vandnot(x, y)           vbicq_u32(y, x)
#define vcmov(x, y, z)          vbslq_u32(z, x, y)
#define vload(m)                vld1q_u32((uint32_t*)(m))
#define vloadu                  vloadu_emu
#define VLOADU_EMULATED         1
#define vor                     vorrq_u32
#define vorn                    vornq_u32
#define vroti_epi32(x, i)       (i > 0 ? vsliq_n_u32(vshrq_n_u32(x, 32-(i)), x, i) : \
                                         vsriq_n_u32(vshlq_n_u32(x, 32+(i)), x, -(i)))
#define vroti_epi64(x, i)       (i > 0 ? (vtype)vsliq_n_u64(vshrq_n_u64((vtype64)(x), 64-(i)), (vtype64)(x), i) : \
                                         (vtype)vsriq_n_u64(vshlq_n_u64((vtype64)(x), 64+(i)), (vtype64)(x), -(i)))
#define vroti16_epi32           vroti_epi32
#define vset1_epi32(x)          vdupq_n_u32(x)
#define vset1_epi64(x)          (vtype)vdupq_n_u64(x)
#define vset_epi32(x3,x2,x1,x0) vcombine_u32(vcreate_u32(((uint64_t)(x1) << 32) | x0), vcreate_u32(((uint64_t)(x3) << 32) | x2))
#define vset_epi64(x1,x0)       (vtype)vcombine_u64(vcreate_u64(x0), vcreate_u64(x1))
#define vsetzero()              vset1_epi32(0)
#define vslli_epi32(x, i)       vshlq_n_u32(x, i)
#define vslli_epi64(x, i)       (vtype)vshlq_n_u64((vtype64)(x), i)
#define vsrli_epi32(x, i)       vshrq_n_u32(x, i)
#define vsrli_epi64(x, i)       (vtype)vshrq_n_u64((vtype64)(x), i)
#define vstore(m, x)            vst1q_u32((uint32_t*)(m), x)
#define vstoreu                 vstoreu_emu
#define VSTOREU_EMULATED        1
#define vunpackhi_epi32(x, y)   (vzipq_u32(x, y)).val[1]
#define vunpackhi_epi64(x, y)   vset_epi64(vgetq_lane_u64((vtype64)(y), 1), vgetq_lane_u64((vtype64)(x), 1))
#define vunpacklo_epi32(x, y)   (vzipq_u32(x, y)).val[0]
#define vunpacklo_epi64(x, y)   vset_epi64(vgetq_lane_u64((vtype64)(y), 0), vgetq_lane_u64((vtype64)(x), 0))
#define vxor                    veorq_u32

static inline int vanyeq_epi32(vtype x, vtype y)
{
	vtype z = vceqq_u32(x, y);
	return vgetq_lane_u32(z, 0) || vgetq_lane_u32(z, 1) ||
	       vgetq_lane_u32(z, 2) || vgetq_lane_u32(z, 3);
}

#define vswap32(x)              (x = (vtype)vrev32q_u8((vtype8)x))
#define vswap64(x)              (x = (vtype)vrev64q_u8((vtype8)x))

#define GATHER64(x,y,z)     { x = vset_epi64 (y[1][z], y[0][z]); }

/*************************** AltiVec (Power) **************************/
#elif __ALTIVEC__
#include <altivec.h>

typedef vector unsigned int vtype32;
typedef vector unsigned long vtype64;
typedef union {
	vtype32 v32;
	vtype64 v64;
	uint32_t s32[SIMD_COEF_32];
	uint64_t s64[SIMD_COEF_64];
} vtype;

#define vadd_epi32(x, y)        (vtype)vec_add((x).v32, (y).v32)
#define vadd_epi64(x, y)        (vtype)vec_add((x).v64, (y).v64)
#define vand(x, y)              (vtype)vec_and((x).v32, (y).v32)
#define vandnot(x, y)           (vtype)vec_andc((y).v32, (x).v32)
#define vcmov(x, y, z)          (vtype)vec_sel((y).v32, (x).v32, (z).v32)
#define vload(m)                (vtype)(vtype32)vec_ld(0, (uint32_t*)(m))
#define vloadu                  vloadu_emu
#define VLOADU_EMULATED         1
#define vor(x, y)               (vtype)vec_or((x).v32, (y).v32)
#define vroti_epi32(x, i)       (vtype)vec_rl((x).v32, (vset1_epi32(i)).v32)
#define vroti_epi64(x, i)       (vtype)vec_rl((x).v64, (vset1_epi64(i)).v64)
#define vroti16_epi32           vroti_epi32
#define vset1_epi32(x)          vset_epi32(x, x, x, x)
#define vset1_epi64(x)          vset_epi64(x, x)
#define vset_epi32(x3,x2,x1,x0) (vtype)(vtype32){x0, x1, x2, x3}
#define vset_epi64(x1,x0)       (vtype)(vtype64){x0, x1}
#define vsetzero()              vset1_epi32(0)
#define vslli_epi32(x, i)       (vtype)vec_sl((x).v32, (vset1_epi32(i)).v32)
#define vslli_epi64(x, i)       (vtype)vec_sl((x).v64, (vset1_epi64(i)).v64)
#define vsrli_epi32(x, i)       (vtype)vec_sr((x).v32, (vset1_epi32(i)).v32)
#define vsrli_epi64(x, i)       (vtype)vec_sr((x).v64, (vset1_epi64(i)).v64)
#define vstore(m, x)            vec_st((x).v32, 0, (uint32_t*)(m))
#define vstoreu                 vstoreu_emu
#define VSTOREU_EMULATED        1
#define vunpackhi_epi32(x, y)   (vtype)vec_mergel((x).v32, (y).v32)
#define vunpackhi_epi64(x, y)   (vtype)(vtype64)vec_mergel((vector long)(x).v64, (vector long)(y).v64)
#define vunpacklo_epi32(x, y)   (vtype)vec_mergeh((x).v32, (y).v32)
#define vunpacklo_epi64(x, y)   (vtype)(vtype64)vec_mergeh((vector long)(x).v64, (vector long)(y).v64)
#define vxor(x, y)              (vtype)vec_xor((x).v32, (y).v32)

#define vanyeq_epi32(x, y)     vec_any_eq((x).v32, (y).v32)

#define vswap32                 vswap32_emu
#define vswap64                 vswap64_emu

#define GATHER64(x,y,z)     { x = vset_epi64 (y[1][z], y[0][z]); }

/*************************** AVX512 and MIC ***************************/
#elif __AVX512F__ || __MIC__
#include <immintrin.h>

typedef __m512i vtype;

#define vadd_epi32              _mm512_add_epi32
#define vadd_epi64              _mm512_add_epi64
#define vand                    _mm512_and_si512
#define vandnot                 _mm512_andnot_si512
#define vcmov                   vcmov_emu
#define VCMOV_EMULATED          1
/*
 * NOTE: AVX2 has it as (base, index, scale) while MIC and AVX512 are
 * different.
 */
#define vgather_epi32(b, i, s)  _mm512_i32gather_epi32(i, (void*)(b), s)
#define vgather_epi64(b, i, s)  _mm512_i64gather_epi64(i, (void*)(b), s)
#define vload(x)                _mm512_load_si512((void*)(x))
#define vloadu(x)               _mm512_loadu_si512((void*)(x))
#define vor                     _mm512_or_si512
#define vroti_epi32             vroti_epi32_emu
#define vroti_epi64             vroti_epi64_emu
#define vroti16_epi32           vroti_epi32
#define vscatter_epi32(b,i,v,s) _mm512_i32scatter_epi32((void*)b, i, v, s)
#define vscatter_epi64(b,i,v,s) _mm512_i64scatter_epi64((void*)b, i, v, s)
#define vset1_epi8              _mm512_set1_epi8
#define vset1_epi32             _mm512_set1_epi32
#define vset1_epi64             _mm512_set1_epi64
#define vset_epi32              _mm512_set_epi32
#define vset_epi64              _mm512_set_epi64
#define vsetzero                _mm512_setzero_si512
#define vshuffle_epi32          _mm512_shuffle_epi32
#define vslli_epi32             _mm512_slli_epi32
#define vslli_epi64             _mm512_slli_epi64
#define vsrli_epi32             _mm512_srli_epi32
#define vsrli_epi64             _mm512_srli_epi64
#define vstore(x, y)            _mm512_store_si512((void*)(x), y)
#define vstoreu(x, y)           _mm512_storeu_si512((void*)(x), y)
#define vunpackhi_epi32         _mm512_unpackhi_epi32
#define vunpackhi_epi64         _mm512_unpackhi_epi64
#define vunpacklo_epi32         _mm512_unpacklo_epi32
#define vunpacklo_epi64         _mm512_unpacklo_epi64
#define vxor                    _mm512_xor_si512

#define vanyeq_epi32(x, y)     _mm512_cmp_epi32_mask(x, y, _MM_CMPINT_EQ)

#define GATHER_4x(x, y, z)                               \
{                                                        \
    vtype indices = vset_epi32(15<<6,14<<6,13<<6,12<<6,  \
                               11<<6,10<<6, 9<<6, 8<<6,  \
                                7<<6, 6<<6, 5<<6, 4<<6,  \
                                3<<6, 2<<6, 1<<6, 0<<6); \
    x = vgather_epi32(&y[z], indices, sizeof(y[z]));     \
}
#define GATHER_2x(x, y, z)                               \
{                                                        \
    vtype indices = vset_epi32(15<<5,14<<5,13<<5,12<<5,  \
                               11<<5,10<<5, 9<<5, 8<<5,  \
                                7<<5, 6<<5, 5<<5, 4<<5,  \
                                3<<5, 2<<5, 1<<5, 0<<5); \
    x = vgather_epi32(&y[z], indices, sizeof(y[z]));     \
}
#define GATHER(x, y, z)                                  \
{                                                        \
    vtype indices = vset_epi32(15<<4,14<<4,13<<4,12<<4,  \
                               11<<4,10<<4, 9<<4, 8<<4,  \
                                7<<4, 6<<4, 5<<4, 4<<4,  \
                                3<<4, 2<<4, 1<<4, 0<<4); \
    x = vgather_epi32(&y[z], indices, sizeof(y[z]));     \
}

#define GATHER64(x, y, z)                                               \
{                                                                       \
    uint64_t stride = sizeof(*y);                                       \
    vtype indices = vset_epi64(7*stride, 6*stride, 5*stride, 4*stride,  \
                               3*stride, 2*stride, 1*stride, 0);        \
    x = vgather_epi64(&y[0][z], indices, 1);                            \
}

#if __AVX512F__
#undef vcmov
#undef VCMOV_EMULATED
#define vcmov(x, y, z)          vternarylogic(x, y, z, 0xE4)
#define vternarylogic           _mm512_ternarylogic_epi32
#endif

#if __AVX512BW__
#define vcmpeq_epi8_mask        (uint64_t)_mm512_cmpeq_epi8_mask
#define vshuffle_epi8           _mm512_shuffle_epi8
#define vshufflehi_epi16        _mm512_shufflehi_epi16
#define vshufflelo_epi16        _mm512_shufflelo_epi16
#define vslli_epi16             _mm512_slli_epi16
#define vsrli_epi16             _mm512_srli_epi16

#define vswap32(n)                                              \
    n = vshuffle_epi8(n, vset_epi32(0x3c3d3e3f, 0x38393a3b,     \
                                    0x34353637, 0x30313233,     \
                                    0x2c2d2e2f, 0x28292a2b,     \
                                    0x24252627, 0x20212223,     \
                                    0x1c1d1e1f, 0x18191a1b,     \
                                    0x14151617, 0x10111213,     \
                                    0x0c0d0e0f, 0x08090a0b,     \
                                    0x04050607, 0x00010203))
#define vswap64(n) \
    n = vshuffle_epi8(n, vset_epi64(0x38393a3b3c3d3e3fULL, \
                                    0x3031323334353637ULL, \
                                    0x28292a2b2c2d2e2fULL, \
                                    0x2021222324252627ULL, \
                                    0x18191a1b1c1d1e1fULL, \
                                    0x1011121314151617ULL, \
                                    0x08090a0b0c0d0e0fULL, \
                                    0x0001020304050607ULL))
#else /* workarounds without AVX512BW */
#define vswap32 vswap32_emu
#define vswap64(x) \
	(x = vshuffle_epi32(x, _MM_SHUFFLE(2, 3, 0, 1)), vswap32(x))

#endif /* __AVX512BW__ */

/* MIC lacks some intrinsics in AVX512F, thus needing emulation. */
#if __MIC__
#define _mm512_set1_epi8(x) _mm512_set1_epi32(x | x<<8 | x<<16 | x<<24)

static inline __m512i _mm512_loadu_si512(void const *addr)
{
	__m512i indices = _mm512_set_epi64(7, 6, 5, 4, 3, 2, 1, 0);
	return is_aligned(addr, 64) ? _mm512_load_si512(addr) :
	                              _mm512_i64gather_epi64(indices, addr, 8);
}

static inline void _mm512_storeu_si512(void *addr, vtype d)
{
	__m512i indices = _mm512_set_epi64(7, 6, 5, 4, 3, 2, 1, 0);

	if (is_aligned(addr, 64))
		_mm512_store_si512(addr, d);
	else
		_mm512_i64scatter_epi64(addr, indices, d, 8);
}
#endif /* __MIC__ */

/******************************** AVX2 ********************************/
#elif __AVX2__
#include <immintrin.h>

typedef __m256i vtype;

#define vadd_epi32              _mm256_add_epi32
#define vadd_epi64              _mm256_add_epi64
#define vand                    _mm256_and_si256
#define vandnot                 _mm256_andnot_si256
#define vcmov                   vcmov_emu
#define VCMOV_EMULATED          1
#define vcmpeq_epi8_mask(a, b)  _mm256_movemask_epi8(_mm256_cmpeq_epi8(a, b))
#define vcmpeq_epi32            _mm256_cmpeq_epi32
#define vcvtsi32                _mm256_cvtsi32_si256
#define vgather_epi32(b, i, s)  _mm256_i32gather_epi32((void*)(b), i, s)
#define vgather_epi64(b, i, s)  _mm256_i64gather_epi64((void*)(b), i, s)
#define vinsert_epi32           _mm256_insert_epi32
#define vload(x)                _mm256_load_si256((void*)(x))
#define vloadu(x)               _mm256_loadu_si256((void*)(x))
#define vmovemask_epi8          _mm256_movemask_epi8
#define vor                     _mm256_or_si256
#define vpermute2x128           _mm256_permute2x128_si256
#define vpermute4x64_epi64      _mm256_permute4x64_epi64
#define vroti_epi32             vroti_epi32_emu
#define vroti_epi64             vroti_epi64_emu
#define vroti16_epi32           vroti_epi32
#define vset1_epi8              _mm256_set1_epi8
#define vset1_epi32             _mm256_set1_epi32
#define vset1_epi64             _mm256_set1_epi64x
#define vset_epi32              _mm256_set_epi32
#define vset_epi64              _mm256_set_epi64x
#define vsetzero                _mm256_setzero_si256
#define vshuffle_epi8           _mm256_shuffle_epi8
#define vshuffle_epi32          _mm256_shuffle_epi32
#define vshufflehi_epi16        _mm256_shufflehi_epi16
#define vshufflelo_epi16        _mm256_shufflelo_epi16
#define vslli_epi16             _mm256_slli_epi16
#define vslli_epi32             _mm256_slli_epi32
#define vslli_epi64             _mm256_slli_epi64
#define vsrli_epi16             _mm256_srli_epi16
#define vsrli_epi32             _mm256_srli_epi32
#define vsrli_epi64             _mm256_srli_epi64
#define vstore(x, y)            _mm256_store_si256((void*)(x), y)
#define vstoreu(x, y)           _mm256_storeu_si256((void*)(x), y)
#define vunpackhi_epi32         _mm256_unpackhi_epi32
#define vunpackhi_epi64         _mm256_unpackhi_epi64
#define vunpacklo_epi32         _mm256_unpacklo_epi32
#define vunpacklo_epi64         _mm256_unpacklo_epi64
#define vxor                    _mm256_xor_si256

#define vanyeq_epi32(x, y)     vmovemask_epi8(vcmpeq_epi32(x, y))

#define swap_endian_mask                                                \
    _mm256_set_epi32(0x1c1d1e1f, 0x18191a1b, 0x14151617, 0x10111213,    \
                     0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203)

#define swap_endian64_mask                                    \
    vset_epi64(0x18191a1b1c1d1e1fULL, 0x1011121314151617ULL, \
               0x08090a0b0c0d0e0fULL, 0x0001020304050607ULL)

#define vswap32(n)                              \
    (n = vshuffle_epi8(n, swap_endian_mask))

#define vswap64(n)                              \
    (n = vshuffle_epi8(n, swap_endian64_mask))

#define GATHER_4x(x, y, z)                           \
{                                                    \
    vtype indices = vset_epi32(7<<6,6<<6,5<<6,4<<6,  \
                               3<<6,2<<6,1<<6,0<<6); \
    x = vgather_epi32(&y[z], indices, sizeof(y[z])); \
}
#define GATHER_2x(x, y, z)                           \
{                                                    \
    vtype indices = vset_epi32(7<<5,6<<5,5<<5,4<<5,  \
                               3<<5,2<<5,1<<5,0<<5); \
    x = vgather_epi32(&y[z], indices, sizeof(y[z])); \
}
#define GATHER(x, y, z)                              \
{                                                    \
    vtype indices = vset_epi32(7<<4,6<<4,5<<4,4<<4,  \
                               3<<4,2<<4,1<<4,0<<4); \
    x = vgather_epi32(&y[z], indices, sizeof(y[z])); \
}

#define GATHER64(x, y, z)                                         \
{                                                                 \
    uint64_t stride = sizeof(*y);                                 \
    vtype indices = vset_epi64(3*stride, 2*stride, 1*stride, 0);  \
    x = vgather_epi64(&y[0][z], indices, 1);                      \
}

/************************* SSE2/3/4/AVX/XOP ***************************/
#elif __SSE2__

#if __XOP__
#include <x86intrin.h>
#elif __AVX__
#include <immintrin.h>
#elif __SSE4_1__
#include <smmintrin.h>
#elif __SSSE3__
#include <tmmintrin.h>
#endif

#include <emmintrin.h>

typedef __m128i vtype;

#define vadd_epi32              _mm_add_epi32
#define vadd_epi64              _mm_add_epi64
#define vand                    _mm_and_si128
#define vandnot                 _mm_andnot_si128
#if __XOP__
#define vcmov                   _mm_cmov_si128
#else
#define vcmov                   vcmov_emu
#define VCMOV_EMULATED          1
#endif
#define vcmpeq_epi8_mask(a, b)  _mm_movemask_epi8(_mm_cmpeq_epi8(a, b))
#define vcmpeq_epi32            _mm_cmpeq_epi32
#if __SSE4_1__
#define vcvtsi32                _mm_cvtsi32_si128
#endif
#define vinsert_epi32           _mm_insert_epi32
#define vload(x)                _mm_load_si128((const vtype*)(x))
#define vloadu(x)               _mm_loadu_si128((const vtype*)(x))
#define vmovemask_epi8          _mm_movemask_epi8
#define vor                     _mm_or_si128
#define vpermute4x64_epi64      _mm_permute4x64_epi64
#define vpermute2x128           _mm_permute2x128_si128
#if __XOP__
#define vroti_epi32             _mm_roti_epi32
#define vroti16_epi32           _mm_roti_epi32
#define vroti_epi64             _mm_roti_epi64
#else
#define vroti_epi32             vroti_epi32_emu
#define vroti_epi64             vroti_epi64_emu
/* Specialized ROTL16 for SSE4.1 and lower (eg. MD5) */
#if __SSSE3__
#define vroti16_epi32(a, s)     vshuffle_epi8((a), vset_epi32(0x0d0c0f0e, 0x09080b0a, 0x05040706, 0x01000302))
#elif __SSE2__
#define vroti16_epi32(a, s)     vshufflelo_epi16(vshufflehi_epi16((a), 0xb1), 0xb1)
#else
#define vroti16_epi32           vroti_epi32
#endif /* __SSSE3__ */
#endif /* __XOP__ */
#define vset_epi32              _mm_set_epi32
#define vset1_epi8              _mm_set1_epi8
#define vset1_epi32             _mm_set1_epi32
#ifndef _MSC_VER
#define vset1_epi64             _mm_set1_epi64x
#define vset_epi64              _mm_set_epi64x
#else
#define vset1_epi64             _mm_set1_epi64
#define vset_epi64              _mm_set_epi64
#endif
#define vsetzero                _mm_setzero_si128
#if __SSSE3__
#define vshuffle_epi8           _mm_shuffle_epi8
#endif
#define vshuffle_epi32          _mm_shuffle_epi32
#define vshufflehi_epi16        _mm_shufflehi_epi16
#define vshufflelo_epi16        _mm_shufflelo_epi16
#define vslli_epi16             _mm_slli_epi16
#define vslli_epi32             _mm_slli_epi32
#define vslli_epi64             _mm_slli_epi64
#define vsrli_epi16             _mm_srli_epi16
#define vsrli_epi32             _mm_srli_epi32
#define vsrli_epi64             _mm_srli_epi64
#define vstore(x, y)            _mm_store_si128((vtype*)(x), y)
#define vstoreu(x, y)           _mm_storeu_si128((vtype*)(x), y)
#define vunpackhi_epi32         _mm_unpackhi_epi32
#define vunpackhi_epi64         _mm_unpackhi_epi64
#define vunpacklo_epi32         _mm_unpacklo_epi32
#define vunpacklo_epi64         _mm_unpacklo_epi64
#define vxor                    _mm_xor_si128

#define vanyeq_epi32(x, y)     vmovemask_epi8(vcmpeq_epi32(x, y))

#if __SSSE3__

#define swap_endian_mask    \
    vset_epi32(0x0c0d0e0f, 0x08090a0b, 0x04050607, 0x00010203)
#define vswap32(n)              (n = vshuffle_epi8(n, swap_endian_mask))

#define swap_endian64_mask  \
    vset_epi64(0x08090a0b0c0d0e0fULL, 0x0001020304050607ULL)
#define vswap64(n)              (n = vshuffle_epi8(n, swap_endian64_mask))

#else /* Just basic SSE2 */

#define vswap32(n)                                  \
    (n = vxor(                                      \
        vsrli_epi16(                                \
            vroti16_epi32(n,16), 8),                \
            vslli_epi16(vroti16_epi32(n,16), 8)))

#define vswap64(n)                                              \
    (                                                           \
        n = vshufflehi_epi16(vshufflelo_epi16(n, 0xb1), 0xb1),  \
        n = vxor(vslli_epi16(n, 8), vsrli_epi16(n, 8)),         \
        n = vshuffle_epi32(n, 0xb1)                             \
    )

#endif /* __SSSE3__ */

#if __SSE4_1__
#define GATHER_4x(x, y, z)                      \
{                                               \
    x = vcvtsi32(   y[z]   );                   \
    x = vinsert_epi32(x, y[z+(1<<6)], 1);       \
    x = vinsert_epi32(x, y[z+(2<<6)], 2);       \
    x = vinsert_epi32(x, y[z+(3<<6)], 3);       \
}
#define GATHER_2x(x, y, z)                      \
{                                               \
    x = vcvtsi32(   y[z]   );                   \
    x = vinsert_epi32(x, y[z+(1<<5)], 1);       \
    x = vinsert_epi32(x, y[z+(2<<5)], 2);       \
    x = vinsert_epi32(x, y[z+(3<<5)], 3);       \
}
#define GATHER(x, y, z)                         \
{                                               \
    x = vcvtsi32(   y[z]   );                   \
    x = vinsert_epi32(x, y[z+(1<<4)], 1);       \
    x = vinsert_epi32(x, y[z+(2<<4)], 2);       \
    x = vinsert_epi32(x, y[z+(3<<4)], 3);       \
}
#endif /* __SSE4_1__ */

#define GATHER64(x,y,z)     { x = vset_epi64 (y[1][z], y[0][z]); }

#if _MSC_VER && !_M_X64
/*
 * These are slow, but the F'n 32 bit compiler will not build these intrinsics.
 * Only the 64-bit (Win64) MSVC compiler has these as intrinsics. These slow
 * ones let me debug, and develop this code, and work, but use CPU
 */
#define _mm_set_epi64 __mm_set_epi64
#define _mm_set1_epi64 __mm_set1_epi64
_inline __m128i _mm_set_epi64(long long a, long long b)
{
	__m128i x;

	x.m128i_i64[0] = b;
	x.m128i_i64[1] = a;
	return x;
}
_inline __m128i _mm_set1_epi64(long long a)
{
	__m128i x;

	x.m128i_i64[0] = x.m128i_i64[1] = a;
	return x;
}
#define vset1_epi64x(x)         vset_epi64x(x, x)
#define vset_epi64x(x1, x0)     (vtype)(vtype64){x0, x1}
#endif

/******************************** MMX *********************************/

#elif __MMX__
#include <mmintrin.h>

typedef __m64i vtype;

#error MMX intrinsics not implemented (contributions are welcome!)

#endif /* __SIMD__ elif __SIMD__ elif __SIMD__ */

/************************* COMMON STUFF BELOW *************************/

#ifdef _MSC_VER
#define MEM_ALIGN_SIMD			16
#define INLINE _inline
#else
#define MEM_ALIGN_SIMD          (SIMD_COEF_32 * 4)
#define INLINE inline
#endif

#if VLOADU_EMULATED
static INLINE vtype vloadu_emu(const void *addr)
{
	if (is_aligned(addr, MEM_ALIGN_SIMD))
		return vload(addr);
	else {
		JTR_ALIGN(MEM_ALIGN_SIMD) char buf[sizeof(vtype)];

		return vload(memcpy(buf, addr, sizeof(vtype)));
	}
}
#endif

#if VSTOREU_EMULATED
static INLINE void vstoreu_emu(void *addr, vtype v)
{
	if (is_aligned(addr, MEM_ALIGN_SIMD))
		vstore(addr, v);
	else {
		JTR_ALIGN(MEM_ALIGN_SIMD) char buf[sizeof(vtype)];

		vstore(buf, v);
		memcpy(addr, buf, sizeof(vtype));
	}
}
#endif

#define vswap32_emu(x) \
	x = vxor(vsrli_epi32(x, 24),                                            \
	         vxor(vslli_epi32(vsrli_epi32(vslli_epi32(x, 8), 24), 8),       \
	              vxor(vsrli_epi32(vslli_epi32(vsrli_epi32(x, 8), 24), 8),  \
                       vslli_epi32(x, 24))))
#define vswap64_emu(x) \
	(x = vxor(vsrli_epi64(x, 32), vslli_epi64(x, 32)), vswap32_emu(x))

#if VCMOV_EMULATED
#if VANDNOT_EMULATED /* currently never */
#define vcmov_emu(x, y, z)      vxor(y, vand(z, vxor(x, y)))
#else
#define vcmov_emu(x, y, z)      vxor(vand(z, x), vandnot(z, y))
#endif
#endif

#if __SSE3__ || __MIC__
#define vslli_epi64a(a, s)      vslli_epi64(a, s)

#else
/* Optimization for really old CPUs for << 1 (for vroti -1) (eg. SHA512) */
#define vslli_epi64a(a, s) ((s) == 1 ?              \
     vadd_epi64((a), (a)) : vslli_epi64((a), (s)))

#endif /* __SSE3__ || __MIC__ */

/*
 * vroti must handle both ROTL and ROTR. If s < 0, then ROTR. Note that
 * the ternary will normally be optimized away!
 */
#define vroti_epi32_emu(a, s)  ((s) < 0 ?                               \
     vxor(vsrli_epi32((a), ~(s) + 1), vslli_epi32((a), 32 + (s))) :     \
     vxor(vslli_epi32((a), (s)), vsrli_epi32((a), 32 - (s))))

#define vroti_epi64_emu(a, s)  ((s) < 0 ?                               \
     vxor(vsrli_epi64((a), ~(s) + 1), vslli_epi64a((a), 64 + (s))) :    \
     vxor(vslli_epi64a((a), (s)), vsrli_epi64((a), 64 - (s))))

#endif /* SIMD_COEF_32 */

#endif /* _SSE_PSEUDO_H */
