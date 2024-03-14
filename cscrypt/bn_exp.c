#include "bn.h"

#ifndef WITH_LIBCRYPTO
//FIXME Not checked on threadsafety yet; after checking please remove this line
/* crypto/bn/bn_exp.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The license and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution license
 * [including the GNU Public License.]
 */
/* ====================================================================
 * Copyright (c) 1998-2000 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */


#include <stdio.h>
#include "bn_lcl.h"

#define TABLE_SIZE  32

/* slow but works */
int BN_mod_mul(BIGNUM *ret, BIGNUM *a, BIGNUM *b, const BIGNUM *m, BN_CTX *ctx)
{
	BIGNUM *t;
	int r = 0;

	bn_check_top(a);
	bn_check_top(b);
	bn_check_top(m);

	BN_CTX_start(ctx);
	if((t = BN_CTX_get(ctx)) == NULL) { goto err; }
	if(a == b)
	{
		if(!BN_sqr(t, a, ctx)) { goto err; }
	}
	else
	{
		if(!BN_mul(t, a, b, ctx)) { goto err; }
	}
	if(!BN_mod(ret, t, m, ctx)) { goto err; }
	r = 1;
err:
	BN_CTX_end(ctx);
	return (r);
}


int BN_mod_exp(BIGNUM *r, BIGNUM *a, const BIGNUM *p, const BIGNUM *m,
			   BN_CTX *ctx)
{
	int ret;

	bn_check_top(a);
	bn_check_top(p);
	bn_check_top(m);

	ret = BN_mod_exp_simple(r, a, p, m, ctx);

	return (ret);
}





/* The old fallback, simple version :-) */
int BN_mod_exp_simple(BIGNUM *r, BIGNUM *a, const BIGNUM *p, const BIGNUM *m,
					  BN_CTX *ctx)
{
	int i, j = 0, bits, ret = 0, wstart = 0, wend = 0, window, wvalue = 0, ts = 0;
	int start = 1;
	BIGNUM *d;
	BIGNUM val[TABLE_SIZE];

	bits = BN_num_bits(p);

	if(bits == 0)
	{
		BN_one(r);
		return (1);
	}

	BN_CTX_start(ctx);
	if((d = BN_CTX_get(ctx)) == NULL) { goto err; }

	BN_init(&(val[0]));
	ts = 1;
	if(!BN_mod(&(val[0]), a, m, ctx)) { goto err; }     /* 1 */

	window = BN_window_bits_for_exponent_size(bits);
	if(window > 1)
	{
		if(!BN_mod_mul(d, &(val[0]), &(val[0]), m, ctx))
			{ goto err; }               /* 2 */
		j = 1 << (window - 1);
		for(i = 1; i < j; i++)
		{
			BN_init(&(val[i]));
			if(!BN_mod_mul(&(val[i]), &(val[i - 1]), d, m, ctx))
				{ goto err; }
		}
		ts = i;
	}

	start = 1;    /* This is used to avoid multiplication etc
             * when there is only the value '1' in the
             * buffer. */
	wstart = bits - 1; /* The top bit of the window */

	if(!BN_one(r)) { goto err; }

	for(;;)
	{
		if(BN_is_bit_set(p, wstart) == 0)
		{
			if(!start)
				if(!BN_mod_mul(r, r, r, m, ctx))
					{ goto err; }
			if(wstart == 0) { break; }
			wstart--;
			continue;
		}
		/* We now have wstart on a 'set' bit, we now need to work out
		 * how bit a window to do.  To do this we need to scan
		 * forward until the last set bit before the end of the
		 * window */
		j = wstart;
		wvalue = 1;
		wend = 0;
		for(i = 1; i < window; i++)
		{
			if(wstart - i < 0) { break; }
			if(BN_is_bit_set(p, wstart - i))
			{
				wvalue <<= (i - wend);
				wvalue |= 1;
				wend = i;
			}
		}

		/* wend is the size of the current window */
		j = wend + 1;
		/* add the 'bytes above' */
		if(!start)
			for(i = 0; i < j; i++)
			{
				if(!BN_mod_mul(r, r, r, m, ctx))
					{ goto err; }
			}

		/* wvalue will be an odd number < 2^window */
		if(!BN_mod_mul(r, r, &(val[wvalue >> 1]), m, ctx))
			{ goto err; }

		/* move the 'window' down further */
		wstart -= wend + 1;
		wvalue = 0;
		start = 0;
		if(wstart < 0) { break; }
	}
	ret = 1;
err:
	BN_CTX_end(ctx);
	for(i = 0; i < ts; i++)
		{ BN_clear_free(&(val[i])); }
	return (ret);
}

int
BN_nnmod(BIGNUM *r, const BIGNUM *m, const BIGNUM *d, BN_CTX *ctx)
{
	/* like BN_mod, but returns non-negative remainder
	 * (i.e., 0 <= r < |d|  always holds)
	 */

	if (!(BN_mod(r, m, d, ctx)))
		return 0;
	if (!r->neg)
		return 1;
	/* now   -|d| < r < 0, so we have to set  r : = r + |d| */
	return (d->neg ? BN_sub : BN_add)(r, r, d);
}

/* solves ax == 1 (mod n) */
BIGNUM *
BN_mod_inverse(BIGNUM *ret, BIGNUM *a, const BIGNUM *n, BN_CTX *ctx)
{
	BIGNUM *A, *B, *X, *Y, *M, *D, *T = NULL;
	int sign;

	bn_check_top(a);
	bn_check_top(n);

	BN_CTX_start(ctx);
	A = BN_CTX_get(ctx);
	B = BN_CTX_get(ctx);
	X = BN_CTX_get(ctx);
	D = BN_CTX_get(ctx);
	M = BN_CTX_get(ctx);
	Y = BN_CTX_get(ctx);
	T = BN_CTX_get(ctx);
	if (T == NULL) goto err;

	if (ret == NULL) goto err;

	BN_one(X);
	BN_zero(Y);
	if (BN_copy(B, a) == NULL) goto err;
	if (BN_copy(A, n) == NULL) goto err;
	A->neg = 0;
	if (B->neg || (BN_ucmp(B, A) >= 0)) {
		if (!BN_nnmod(B, B, A, ctx)) goto err;
	}
	sign = -1;
	/* From  B = a mod |n|, A = |n|  it follows that
	 *
	 *      0 <= B < A,
	 *     -sign*X*a  ==  B   (mod |n|),
	 *      sign*Y*a  ==  A   (mod |n|).
	 */

	if (BN_is_odd(n) && (BN_num_bits(n) <= (BN_BITS <= 32 ? 450 : 2048))) {
		/* Binary inversion algorithm; requires odd modulus.
		 * This is faster than the general algorithm if the modulus
		 * is sufficiently small (about 400 .. 500 bits on 32-bit
		 * sytems, but much more on 64-bit systems)
		 */
		int shift;

		while (!BN_is_zero(B)) {
			/*
			 *      0 < B < |n|,
			 *      0 < A <= |n|,
			 * (1) -sign*X*a  ==  B   (mod |n|),
			 * (2)  sign*Y*a  ==  A   (mod |n|)
			 */

			/* Now divide  B  by the maximum possible power of two in the integers,
			 * and divide  X  by the same value mod |n|.
			 * When we're done, (1) still holds.
			 */
			shift = 0;
			while (!BN_is_bit_set(B, shift)) /* note that 0 < B */ {
				shift++;

				if (BN_is_odd(X)) {
					if (!BN_uadd(X, X, n)) goto err;
				}
				/* now X is even, so we can easily divide it by two */
				if (!BN_rshift1(X, X)) goto err;
			}
			if (shift > 0) {
				if (!BN_rshift(B, B, shift)) goto err;
			}


			/* Same for  A  and  Y.  Afterwards, (2) still holds. */
			shift = 0;
			while (!BN_is_bit_set(A, shift)) /* note that 0 < A */ {
				shift++;

				if (BN_is_odd(Y)) {
					if (!BN_uadd(Y, Y, n)) goto err;
					}
				/* now Y is even */
				if (!BN_rshift1(Y, Y)) goto err;
			}
			if (shift > 0) {
				if (!BN_rshift(A, A, shift)) goto err;
			}

			/* We still have (1) and (2).
			 * Both  A  and  B  are odd.
			 * The following computations ensure that
			 *
			 *     0 <= B < |n|,
			 *      0 < A < |n|,
			 * (1) -sign*X*a  ==  B   (mod |n|),
			 * (2)  sign*Y*a  ==  A   (mod |n|),
			 *
			 * and that either  A  or  B  is even in the next iteration.
			 */
			if (BN_ucmp(B, A) >= 0) {
				/* -sign*(X + Y)*a == B - A  (mod |n|) */
				if (!BN_uadd(X, X, Y)) goto err;
				/* NB: we could use BN_mod_add_quick(X, X, Y, n), but that
				 * actually makes the algorithm slower
				 */
				if (!BN_usub(B, B, A)) goto err;
			} else {
				/*  sign*(X + Y)*a == A - B  (mod |n|) */
				if (!BN_uadd(Y, Y, X)) goto err;
				/* as above, BN_mod_add_quick(Y, Y, X, n) would slow things down */
				if (!BN_usub(A, A, B)) goto err;
			}
		}
	} else {
		/* general inversion algorithm */

		while (!BN_is_zero(B)) {
			BIGNUM *tmp;

			/*
			 *      0 < B < A,
			 * (*) -sign*X*a  ==  B   (mod |n|),
			 *      sign*Y*a  ==  A   (mod |n|)
			 */

			/* (D, M) : = (A/B, A%B) ... */
			if (BN_num_bits(A) == BN_num_bits(B)) {
				if (!BN_one(D)) goto err;
				if (!BN_sub(M, A, B)) goto err;
			} else if (BN_num_bits(A) == BN_num_bits(B) + 1) {
				/* A/B is 1, 2, or 3 */
				if (!BN_lshift1(T, B)) goto err;
				if (BN_ucmp(A, T) < 0) {
					/* A < 2*B, so D = 1 */
					if (!BN_one(D)) goto err;
					if (!BN_sub(M, A, B)) goto err;
				} else {
					/* A >= 2*B, so D = 2 or D = 3 */
					if (!BN_sub(M, A, T)) goto err;
					if (!BN_add(D, T, B)) goto err;
					/* use D ( := 3 * B) as temp */
					if (BN_ucmp(A, D) < 0) {
						/* A < 3*B, so D = 2 */
						if (!BN_set_word(D, 2)) goto err;
						/* M ( = A - 2*B) already has the correct value */
					} else {
						/* only D = 3 remains */
						if (!BN_set_word(D, 3)) goto err;
						/* currently  M = A - 2 * B,
						 * but we need  M = A - 3 * B
						 */
						if (!BN_sub(M, M, B)) goto err;
					}
				}
			} else {
				if (!BN_div(D, M, A, B, ctx)) goto err;
			}

			/* Now
			 *      A = D*B + M;
			 * thus we have
			 * (**)  sign*Y*a  ==  D*B + M   (mod |n|).
			 */

			tmp = A; /* keep the BIGNUM object, the value does not matter */

			/* (A, B) : = (B, A mod B) ... */
			A = B;
			B = M;
			/* ... so we have  0 <= B < A  again */

			/* Since the former  M  is now  B  and the former  B  is now  A,
			 * (**) translates into
			 *       sign*Y*a  ==  D*A + B    (mod |n|),
			 * i.e.
			 *       sign*Y*a - D*A  ==  B    (mod |n|).
			 * Similarly, (*) translates into
			 *      -sign*X*a  ==  A          (mod |n|).
			 *
			 * Thus,
			 *   sign*Y*a + D*sign*X*a  ==  B  (mod |n|),
			 * i.e.
			 *        sign*(Y + D*X)*a  ==  B  (mod |n|).
			 *
			 * So if we set  (X, Y, sign) : = (Y + D*X, X, -sign), we arrive back at
			 *      -sign*X*a  ==  B   (mod |n|),
			 *       sign*Y*a  ==  A   (mod |n|).
			 * Note that  X  and  Y  stay non-negative all the time.
			 */

			/* most of the time D is very small, so we can optimize tmp : = D*X+Y */
			if (BN_is_one(D)) {
				if (!BN_add(tmp, X, Y)) goto err;
			} else {
				if (BN_is_word(D, 2)) {
					if (!BN_lshift1(tmp, X)) goto err;
				} else if (BN_is_word(D, 4)) {
					if (!BN_lshift(tmp, X, 2)) goto err;
				} else if (D->top == 1) {
					if (!BN_copy(tmp, X)) goto err;
					if (!BN_mul_word(tmp, D->d[0])) goto err;
				} else {
					if (!BN_mul(tmp, D, X, ctx)) goto err;
				}
				if (!BN_add(tmp, tmp, Y)) goto err;
			}

			M = Y; /* keep the BIGNUM object, the value does not matter */
			Y = X;
			X = tmp;
			sign = -sign;
		}
	}

	/*
	 * The while loop (Euclid's algorithm) ends when
	 *      A == gcd(a, n);
	 * we have
	 *       sign*Y*a  ==  A  (mod |n|),
	 * where  Y  is non-negative.
	 */

	if (sign < 0) {
		if (!BN_sub(Y, n, Y)) goto err;
	}
	/* Now  Y*a  ==  A  (mod |n|).  */


	if (BN_is_one(A)) {
		/* Y*a == 1  (mod |n|) */
		if (!Y->neg && BN_ucmp(Y, n) < 0) {
			if (!BN_copy(ret, Y)) goto err;
		} else {
			if (!BN_nnmod(ret, Y, n, ctx)) goto err;
		}
	} else {
		goto err;
	}
err:
	BN_CTX_end(ctx);
	return (ret);
}

#endif
