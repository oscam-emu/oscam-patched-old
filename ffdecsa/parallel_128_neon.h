/* FFdecsa -- fast decsa algorithm
 *
 * Copyright (C) 2007 Dark Avenger
 *               2003-2004  fatih89r
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#include <arm_neon.h>

#if __GNUC__ > 10
#define __XOREQ_8_BY__
#endif

/* group */
//#define __GROUP_u8x16__
//#define __GROUP_u16x8__
//#define __GROUP_u32x4__
#define __GROUP_u64x2__

/* batch */
//#define __BATCH_u8x8__
//#define __BATCH_u16x4__
//#define __BATCH_u32x2__
//#define __BATCH_u64x1__
//#define __BATCH_u8x16__
//#define __BATCH_u16x8__
//#define __BATCH_u32x4__
#define __BATCH_u64x2__

/* span */
#define __SPAN_16__

/* GROUP */
#define FF0() ff0
#define FF1() ff1

#if defined(__GROUP_u8x16__)
	#define GROUP_PARALLELISM 128
	typedef uint8x16_t group;
	static const group ff0 = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
	static const group ff1 = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	#define FFAND(a,b) vandq_u8(a,b)
	#define FFOR(a,b)  vorrq_u8(a,b)
	#define FFXOR(a,b) veorq_u8(a,b)
	#define FFNOT(a)   vmvnq_u8(a)
#elif defined(__GROUP_u16x8__)
	#define GROUP_PARALLELISM 128
	typedef uint16x8_t group;
	static const group ff0 = { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
	static const group ff1 = { 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff };
	#define FFAND(a,b) vandq_u16(a,b)
	#define FFOR(a,b)  vorrq_u16(a,b)
	#define FFXOR(a,b) veorq_u16(a,b)
	#define FFNOT(a)   vmvnq_u16(a)
#elif defined(__GROUP_u32x4__)
	#define GROUP_PARALLELISM 128
	typedef uint32x4_t group;
	static const group ff0 = { 0x0, 0x0, 0x0, 0x0 };
	static const group ff1 = { 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
	#define FFAND(a,b) vandq_u32(a,b)
	#define FFOR(a,b)  vorrq_u32(a,b)
	#define FFXOR(a,b) veorq_u32(a,b)
	#define FFNOT(a)   vmvnq_u32(a)
#else /* (__GROUP_u64x2__) */
	#define GROUP_PARALLELISM 128
	typedef uint64x2_t group;
	static const group ff0 = { 0x0, 0x0 };
	static const group ff1 = { 0xffffffffffffffff, 0xffffffffffffffff };
	#define FFAND(a,b) vandq_u64(a,b)
	#define FFOR(a,b)  vorrq_u64(a,b)
	#define FFXOR(a,b) veorq_u64(a,b)
	#if 0
		#define FFNOT(a) vreinterpretq_u64_u8(vmvnq_u8(vreinterpretq_u8_u64(a)))
	#else
		#define FFNOT(a) vreinterpretq_u64_u32(vmvnq_u32(vreinterpretq_u32_u64(a)))
	#endif
#endif

/* BATCH */
#define B_FFN_ALL_29() ff29
#define B_FFN_ALL_02() ff02
#define B_FFN_ALL_04() ff04
#define B_FFN_ALL_10() ff10
#define B_FFN_ALL_40() ff40
#define B_FFN_ALL_80() ff80

#if defined(__BATCH_u8x8__)
	#define BYTES_PER_BATCH 8
	typedef uint8x8_t batch;
	static const batch ff29 = { 0x29, 0x29, 0x29, 0x29, 0x29, 0x29, 0x29, 0x29 };
	static const batch ff02 = { 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02 };
	static const batch ff04 = { 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04 };
	static const batch ff10 = { 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10 };
	static const batch ff40 = { 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40 };
	static const batch ff80 = { 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 };
	#define B_FFAND(a,b)  vand_u8(a,b)
	#define B_FFOR(a,b)   vorr_u8(a,b)
	#define B_FFXOR(a,b)  veor_u8(a,b)
	#define B_FFSH8L(a,n) vshl_n_u8(a,n)
	#define B_FFSH8R(a,n) vshr_n_u8(a,n)
	typedef batch _u64;
#elif defined(__BATCH_u16x4__)
	#define BYTES_PER_BATCH 8
	typedef uint16x4_t batch;
	static const batch ff29 = { 0x2929, 0x2929, 0x2929, 0x2929 };
	static const batch ff02 = { 0x0202, 0x0202, 0x0202, 0x0202 };
	static const batch ff04 = { 0x0404, 0x0404, 0x0404, 0x0404 };
	static const batch ff10 = { 0x1010, 0x1010, 0x1010, 0x1010 };
	static const batch ff40 = { 0x4040, 0x4040, 0x4040, 0x4040 };
	static const batch ff80 = { 0x8080, 0x8080, 0x8080, 0x8080 };
	#define B_FFAND(a,b)  vand_u16(a,b)
	#define B_FFOR(a,b)   vorr_u16(a,b)
	#define B_FFXOR(a,b)  veor_u16(a,b)
	#define B_FFSH8L(a,n) vshl_n_u16(a,n)
	#define B_FFSH8R(a,n) vshr_n_u16(a,n)
	typedef batch _u64;
#elif defined(__BATCH_u32x2__)
	#define BYTES_PER_BATCH 8
	typedef uint32x2_t batch;
	static const batch ff29 = { 0x29292929, 0x29292929 };
	static const batch ff02 = { 0x02020202, 0x02020202 };
	static const batch ff04 = { 0x04040404, 0x04040404 };
	static const batch ff10 = { 0x10101010, 0x10101010 };
	static const batch ff40 = { 0x40404040, 0x40404040 };
	static const batch ff80 = { 0x80808080, 0x80808080 };
	#define B_FFAND(a,b)  vand_u32(a,b)
	#define B_FFOR(a,b)   vorr_u32(a,b)
	#define B_FFXOR(a,b)  veor_u32(a,b)
	#define B_FFSH8L(a,n) vshl_n_u32(a,n)
	#define B_FFSH8R(a,n) vshr_n_u32(a,n)
	typedef batch _u64;
#elif defined(__BATCH_u64x1__)
	#define BYTES_PER_BATCH 8
	typedef uint64x1_t batch;
	static const batch ff29 = { 0x2929292929292929 };
	static const batch ff02 = { 0x0202020202020202 };
	static const batch ff04 = { 0x0404040404040404 };
	static const batch ff10 = { 0x1010101010101010 };
	static const batch ff40 = { 0x4040404040404040 };
	static const batch ff80 = { 0x8080808080808080 };
	#define B_FFAND(a,b)   vand_u64(a,b)
	#define B_FFOR(a,b)    vorr_u64(a,b)
	#define B_FFXOR(a,b)   veor_u64(a,b)
	#define B_FFSH8L(a,n)  vshl_n_u64(a,n)
	#define B_FFSH8R(a,n)  vshr_n_u64(a,n)
	typedef batch _u64;
#elif defined(__BATCH_u8x16__)
	#define BYTES_PER_BATCH 16
	typedef uint8x16_t batch;
	static const batch ff29 = { 0x29, 0x29, 0x29, 0x29, 0x29, 0x29, 0x29, 0x29, 0x29, 0x29, 0x29, 0x29, 0x29, 0x29, 0x29, 0x29 };
	static const batch ff02 = { 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02 };
	static const batch ff04 = { 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04, 0x04 };
	static const batch ff10 = { 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10 };
	static const batch ff40 = { 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40 };
	static const batch ff80 = { 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 };
	#define B_FFAND(a,b)  vandq_u8(a,b)
	#define B_FFOR(a,b)   vorrq_u8(a,b)
	#define B_FFXOR(a,b)  veorq_u8(a,b)
	#define B_FFSH8L(a,n) vshlq_n_u8(a,n)
	#define B_FFSH8R(a,n) vshrq_n_u8(a,n)
	typedef uint8x8_t _u64;
	#ifndef __SPAN_16__
		#define __SPAN_16__
	#endif
#elif defined(__BATCH_u16x8__)
	#define BYTES_PER_BATCH 16
	typedef uint16x8_t batch;
	static const batch ff29 = { 0x2929, 0x2929, 0x2929, 0x2929, 0x2929, 0x2929, 0x2929, 0x2929 };
	static const batch ff02 = { 0x0202, 0x0202, 0x0202, 0x0202, 0x0202, 0x0202, 0x0202, 0x0202 };
	static const batch ff04 = { 0x0404, 0x0404, 0x0404, 0x0404, 0x0404, 0x0404, 0x0404, 0x0404 };
	static const batch ff10 = { 0x1010, 0x1010, 0x1010, 0x1010, 0x1010, 0x1010, 0x1010, 0x1010 };
	static const batch ff40 = { 0x4040, 0x4040, 0x4040, 0x4040, 0x4040, 0x4040, 0x4040, 0x4040 };
	static const batch ff80 = { 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080, 0x8080 };
	#define B_FFAND(a,b)  vandq_u16(a,b)
	#define B_FFOR(a,b)   vorrq_u16(a,b)
	#define B_FFXOR(a,b)  veorq_u16(a,b)
	#define B_FFSH8L(a,n) vshlq_n_u16(a,n)
	#define B_FFSH8R(a,n) vshrq_n_u16(a,n)
	typedef uint16x4_t _u64;
	#ifndef __SPAN_16__
		#define __SPAN_16__
	#endif
#elif defined(__BATCH_u32x4__)
	#define BYTES_PER_BATCH 16
	typedef uint32x4_t batch;
	static const batch ff29 = { 0x29292929, 0x29292929, 0x29292929, 0x29292929 };
	static const batch ff02 = { 0x02020202, 0x02020202, 0x02020202, 0x02020202 };
	static const batch ff04 = { 0x04040404, 0x04040404, 0x04040404, 0x04040404 };
	static const batch ff10 = { 0x10101010, 0x10101010, 0x10101010, 0x10101010 };
	static const batch ff40 = { 0x40404040, 0x40404040, 0x40404040, 0x40404040 };
	static const batch ff80 = { 0x80808080, 0x80808080, 0x80808080, 0x80808080 };
	#define B_FFAND(a,b)  vandq_u32(a,b)
	#define B_FFOR(a,b)   vorrq_u32(a,b)
	#define B_FFXOR(a,b)  veorq_u32(a,b)
	#define B_FFSH8L(a,n) vshlq_n_u32(a,n)
	#define B_FFSH8R(a,n) vshrq_n_u32(a,n)
	typedef uint32x2_t _u64;
	#ifndef __SPAN_16__
		#define __SPAN_16__
	#endif
#else /* (__BATCH_u64x2__) */
	#define BYTES_PER_BATCH 16
	typedef uint64x2_t batch;
	static const batch ff29 = { 0x2929292929292929, 0x2929292929292929 };
	static const batch ff02 = { 0x0202020202020202, 0x0202020202020202 };
	static const batch ff04 = { 0x0404040404040404, 0x0404040404040404 };
	static const batch ff10 = { 0x1010101010101010, 0x1010101010101010 };
	static const batch ff40 = { 0x4040404040404040, 0x4040404040404040 };
	static const batch ff80 = { 0x8080808080808080, 0x8080808080808080 };
	#define B_FFAND(a,b)  vandq_u64(a,b)
	#define B_FFOR(a,b)   vorrq_u64(a,b)
	#define B_FFXOR(a,b)  veorq_u64(a,b)
	#define B_FFSH8L(a,n) vshlq_n_u64(a,n)
	#define B_FFSH8R(a,n) vshrq_n_u64(a,n)
	typedef uint64x1_t _u64;
	#ifndef __SPAN_16__
		#define __SPAN_16__
	#endif
#endif

#define MEMALIGN_VAL 16
#define M_EMPTY()

#undef XOR_8_BY
#if defined(__BATCH_u8x8__) || defined(__BATCH_u8x16__)
	#define XOR_8_BY(d,s1,s2) vst1_u8(d, veor_u8(vld1_u8(s1), vld1_u8(s2)))
#elif defined(__BATCH_u16x4__) || defined(__BATCH_u16x8__)
	#define XOR_8_BY(d,s1,s2) vst1_u8(d, vreinterpret_u8_u16(veor_u16(vreinterpret_u16_u8(vld1_u8(s1)), vreinterpret_u16_u8(vld1_u8(s2)))))
#elif defined(__BATCH_u32x2__) || defined(__BATCH_u32x4__)
	#define XOR_8_BY(d,s1,s2) vst1_u8(d, vreinterpret_u8_u32(veor_u32(vreinterpret_u32_u8(vld1_u8(s1)), vreinterpret_u32_u8(vld1_u8(s2)))))
#else /* (__BATCH_u64x1__) || (__BATCH_u64x2__) */
	#define XOR_8_BY(d,s1,s2) vst1_u8(d, vreinterpret_u8_u64(veor_u64(vreinterpret_u64_u8(vld1_u8(s1)), vreinterpret_u64_u8(vld1_u8(s2)))))
#endif
#undef XOREQ_8_BY
#define XOREQ_8_BY(d,s) XOR_8_BY(d,d,s)
#undef COPY_8_BY
#define COPY_8_BY(d,s) *(_u64*)(d) = *(_u64*)(s)

/* span */
#if defined(__SPAN_16__)
	#undef BEST_SPAN
	#define BEST_SPAN            16
	#undef XOR_BEST_BY
	#if defined(__GROUP_u8x16__)
		#define XOR_BEST_BY(d,s1,s2) vst1q_u8(d, veorq_u8(vld1q_u8(s1), vld1q_u8(s2)))
	#elif defined(__GROUP_u16x8__)
		#if 0
			#define XOR_BEST_BY(d,s1,s2) vst1q_u16((uint16_t *)d, veorq_u16(vld1q_u16((const uint16_t *)s1), vld1q_u16((const uint16_t *)s2)))
		#else
			#define XOR_BEST_BY(d,s1,s2) vst1q_u8(d, vreinterpretq_u8_u16(veorq_u16(vreinterpretq_u16_u8(vld1q_u8(s1)), vreinterpretq_u16_u8(vld1q_u8(s2)))))
		#endif
	#elif defined(__GROUP_u32x4__)
		#if 0
			#define XOR_BEST_BY(d,s1,s2) vst1q_u32((uint32_t *)d, veorq_u32(vld1q_u16((const uint32_t *)s1), vld1q_u32((const uint32_t *)s2)))
		#else
			#define XOR_BEST_BY(d,s1,s2) vst1q_u8(d, vreinterpretq_u8_u32(veorq_u32(vreinterpretq_u32_u8(vld1q_u8(s1)), vreinterpretq_u32_u8(vld1q_u8(s2)))))
		#endif
	#else /* (__GROUP_u64x2__) */
		#if 0
			#define XOR_BEST_BY(d,s1,s2) vst1q_u64((uint64_t *)d, veorq_u64(vld1q_u64((const uint64_t *)s1), vld1q_u64((const uint64_t *)s2)))
		#else
			#define XOR_BEST_BY(d,s1,s2) vst1q_u8(d, vreinterpretq_u8_u64(veorq_u64(vreinterpretq_u64_u8(vld1q_u8(s1)), vreinterpretq_u64_u8(vld1q_u8(s2)))))
		#endif
	#endif
	#undef XOREQ_BEST_BY
	#define XOREQ_BEST_BY(d,s)   XOR_BEST_BY(d,d,s)
	#undef COPY_BEST_BY
	#define COPY_BEST_BY(d,s)    *(group*)(d) = *(group*)(s)
#else /* (__SPAN_8__) */
	#undef BEST_SPAN
	#define BEST_SPAN            8
	#undef XOR_BEST_BY
	#define XOR_BEST_BY(d,s1,s2) XOR_8_BY(d,s1,s2)
	#undef XOREQ_BEST_BY
	#define XOREQ_BEST_BY(d,s)   XOREQ_8_BY(d,s)
	#undef COPY_BEST_BY
	#define COPY_BEST_BY(d,s)    COPY_8_BY(d,s)
#endif /* end span */

#if 0 /* fftable */
#include "fftable.h"
#else
/* 64 rows of 128 bits */
inline static void FFTABLEIN(unsigned char *tab, int g, unsigned char *data) { *(((_u64*)tab)+g)=*((_u64*)data); }
inline static void FFTABLEOUT(unsigned char *data, unsigned char *tab, int g) { *((_u64*)data)=*(((_u64*)tab)+g); }
inline static void FFTABLEOUTXORNBY(int n, unsigned char *data, unsigned char *tab, int g)
{
  int j;
  for(j=0;j<n;j++) { *(data+j)^=*(tab+8*g+j); }
}
#endif /* end fftable */
