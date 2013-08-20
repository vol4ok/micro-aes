#include "defines.h"
#include "aes.h"

#define lfsr2(y) ((y & 0x80) ? y << 1 ^ 0x11b : y << 1)

void aes_encrypt(aes_context_t* ctx, const u8* in, u8* out)
{
	u32* u = p32(in);
	u32* s = p32(out);
	u32  t[4];
	u32* rk = ctx->ekey;
	u32* te32 = ctx->te32;
	u8*  te = ctx->te;
	u32  r = ROUNDS-1;

	/* add round key */
	s[0] = u[0] ^ *rk++;
	s[1] = u[1] ^ *rk++;
	s[2] = u[2] ^ *rk++;
	s[3] = u[3] ^ *rk++;

	/* do subBytes + shiftRows + mixColomns + addRoundKey x 13 times */
	while(1) {
		t[0] =      te32[d8(s[0]      )]
			^ ror32(te32[d8(s[1] >>  8)], 24)
			^ ror32(te32[d8(s[2] >> 16)], 16)
			^ ror32(te32[d8(s[3] >> 24)],  8)
			^ *rk++;

		t[1] =      te32[d8(s[1]      )]
			^ ror32(te32[d8(s[2] >>  8)], 24)
			^ ror32(te32[d8(s[3] >> 16)], 16)
			^ ror32(te32[d8(s[0] >> 24)],  8)
			^ *rk++;

		t[2] =      te32[d8(s[2]      )]
			^ ror32(te32[d8(s[3] >>  8)], 24)
			^ ror32(te32[d8(s[0] >> 16)], 16)
			^ ror32(te32[d8(s[1] >> 24)],  8)
			^ *rk++;

		t[3] =      te32[d8(s[3]      )]
			^ ror32(te32[d8(s[0] >>  8)], 24)
			^ ror32(te32[d8(s[1] >> 16)], 16)
			^ ror32(te32[d8(s[2] >> 24)],  8)
			^ *rk++;

		if (--r == 0)
			break;

		s[0] = t[0];
		s[1] = t[1];
		s[2] = t[2];
		s[3] = t[3];
	}

	/* do last round without mixColomns */

	s[0] = te[d8(t[0]      )]
		^  te[d8(t[1] >>  8)] << 8
		^  te[d8(t[2] >> 16)] << 16
		^  te[d8(t[3] >> 24)] << 24
		^  *rk++;

	s[1] = te[d8(t[1]      )]
		^  te[d8(t[2] >>  8)] << 8
		^  te[d8(t[3] >> 16)] << 16
		^  te[d8(t[0] >> 24)] << 24
		^  *rk++;

	s[2] = te[d8(t[2]      )] 
		^  te[d8(t[3] >>  8)] << 8
		^  te[d8(t[0] >> 16)] << 16
		^  te[d8(t[1] >> 24)] << 24
		^  *rk++;

	s[3] = te[d8(t[3]      )] 
		^  te[d8(t[0] >>  8)] << 8
		^  te[d8(t[1] >> 16)] << 16
		^  te[d8(t[2] >> 24)] << 24
		^  *rk++;
}

void aes_decrypt(aes_context_t* ctx, const u8* in, u8* out)
{
	u32* u = p32(in);
	u32* s = p32(out);
	u32  t[4];
	u32* rk = ctx->dkey;
	u32* td32 = ctx->td32;
	u8*  td = ctx->td;
	u32  r = ROUNDS-1;

	/* add round key */
	s[0] = u[0] ^ *rk++;
	s[1] = u[1] ^ *rk++;
	s[2] = u[2] ^ *rk++;
	s[3] = u[3] ^ *rk++;

	/* do subBytes + shiftRows + mixColomns + addRoundKey x 13 times */
	while(1) {
		t[0] =      td32[d8(s[0]      )]
			^ ror32(td32[d8(s[3] >>  8)], 24)
			^ ror32(td32[d8(s[2] >> 16)], 16)
			^ ror32(td32[d8(s[1] >> 24)],  8)
			^ *rk++;

		t[1] =      td32[d8(s[1]      )]
			^ ror32(td32[d8(s[0] >>  8)], 24)
			^ ror32(td32[d8(s[3] >> 16)], 16)
			^ ror32(td32[d8(s[2] >> 24)],  8)
			^ *rk++;

		t[2] =      td32[d8(s[2]      )]
			^ ror32(td32[d8(s[1] >>  8)], 24)
			^ ror32(td32[d8(s[0] >> 16)], 16)
			^ ror32(td32[d8(s[3] >> 24)],  8)
			^ *rk++;

		t[3] =      td32[d8(s[3]      )]
			^ ror32(td32[d8(s[2] >>  8)], 24)
			^ ror32(td32[d8(s[1] >> 16)], 16)
			^ ror32(td32[d8(s[0] >> 24)],  8)
			^ *rk++;

		if (--r == 0)
			break;

		s[0] = t[0];
		s[1] = t[1];
		s[2] = t[2];
		s[3] = t[3];
	}

	/* do last round without mixColomns */

	s[0] = td[d8(t[0]      )]
		^  td[d8(t[3] >>  8)] << 8
		^  td[d8(t[2] >> 16)] << 16
		^  td[d8(t[1] >> 24)] << 24
		^  *rk++;

	s[1] = td[d8(t[1]      )]
		^  td[d8(t[0] >>  8)] << 8
		^  td[d8(t[3] >> 16)] << 16
		^  td[d8(t[2] >> 24)] << 24
		^  *rk++;

	s[2] = td[d8(t[2]      )] 
		^  td[d8(t[1] >>  8)] << 8
		^  td[d8(t[0] >> 16)] << 16
		^  td[d8(t[3] >> 24)] << 24
		^  *rk++;

	s[3] = td[d8(t[3]      )] 
		^  td[d8(t[2] >>  8)] << 8
		^  td[d8(t[1] >> 16)] << 16
		^  td[d8(t[0] >> 24)] << 24
		^  *rk++;
}

void aes_set_key(aes_context_t* ctx, u8* key)
{
	u32* ek   = ctx->ekey;
	u32* dk   = ctx->dkey;
	u8*  te  = ctx->te;
	u32* td32  = ctx->td32;
	u32  rcon = 1;
	u32  i    = 7;

	/* copy key */
	memcpy(ek, key, AES_KEY_SIZE);

	/* 1. expand encrypt key */

	while (1) {
		u32 t = ek[7];
		ek[8] = ek[0] 
			^ (te[d8(t >> 8 )]) 
			^ (te[d8(t >> 16)]) << 8
			^ (te[d8(t >> 24)]) << 16
			^ (te[d8(t      )]) << 24
			^ rcon;

		ek[ 9] = ek[1] ^ ek[ 8];
		ek[10] = ek[2] ^ ek[ 9];
		ek[11] = ek[3] ^ ek[10];

		if (--i == 0)
			break;

		t = ror32(ek[11], 24);
		ek[12] = ek[4] 
			^ (te[d8(t >> 8 )])
			^ (te[d8(t >> 16)]) << 8
			^ (te[d8(t >> 24)]) << 16
			^ (te[d8(t      )]) << 24;

		ek[13] = ek[5] ^ ek[12];
		ek[14] = ek[6] ^ ek[13];
		ek[15] = ek[7] ^ ek[14];

		ek += 8;
		rcon <<= 1;
	}

	/* 2. expand decrypt key */

	ek = ctx->ekey;

	/* invert the order of the round keys: */
	for (i = 0; i <= 4*ROUNDS; i += 4) {
		dk[i + 0] = ek[4*ROUNDS - i + 0]; 
		dk[i + 1] = ek[4*ROUNDS - i + 1]; 
		dk[i + 2] = ek[4*ROUNDS - i + 2]; 
		dk[i + 3] = ek[4*ROUNDS - i + 3];
	}

	/* apply the inverse mixColumn transform */
	for (i = 0; i < (ROUNDS-1) * 4; i++) {
		u32 t = dk[i + 4];
		dk[i + 4] = td32[te[d8(t      )]]
			^ ror32(td32[te[d8(t >>  8)]], 24)
			^ ror32(td32[te[d8(t >> 16)]], 16) 
			^ ror32(td32[te[d8(t >> 24)]],  8); 
	}

}

void aes_init(aes_context_t* ctx)
{
	u8 exp[256];
	u8 log[256];
	u8 x, y;

	/* generate log and exp table with base (x+1) */
	x = 0;
	y = 1;
	do {
		exp[x] = y;
		log[y] = x;
		/* y = y*(x+1) = y*x+y mod (x^8+x^4+x^3+x+1) */
		y ^= (y & 0x80) ? y << 1 ^ 0x11b : y << 1; 
	} while(++x);
	exp[255] = 0;
	log[0]   = 0;

	/* generate S-Box and inverse S-box*/
	x = 0;
	do {
		/* take multiplicative inverse in finite field GF(2^8) */
		y = exp[255 - log[x]];
		/* apply affine transform y' = y[i]+y[i+4]+y[i+5]+y[i+6]+y[i+7]+c[i]*/
		y ^= y << 1 ^ y << 2 ^ y << 3 ^ y << 4 ^ y >> 4 ^ y >> 5 ^ y >> 6 ^ y >> 7 ^ 0x63;
		ctx->te[x] = y;
		ctx->td[y] = x;
	} while(++x);

	/* generate table for mixColomn optimization */
	x = 0;
	do {
		u8 u;
		y = ctx->te[x];
		u = lfsr2(y);

		ctx->te32[x] = (u ^ y) << 24 ^ y << 16 ^ y << 8 ^ u;

		y = ctx->td[x];
		ctx->td32[x] = !y ? y :
			exp[(0x68 + log[y]) % 255] << 24 ^
			exp[(0xEE + log[y]) % 255] << 16 ^
			exp[(0xC7 + log[y]) % 255] <<  8 ^
			exp[(0xDF + log[y]) % 255] <<  0;     
	} while(++x);
}

void aes_ctr128_inc(u8* counter) {
	u32* c = p32(counter);

	if (c[3] = bswap32(bswap32(c[3])+1))
		return;
	if (c[2] = bswap32(bswap32(c[2])+1))
		return;
	if (c[1] = bswap32(bswap32(c[1])+1))
		return;
	if (c[0] = bswap32(bswap32(c[0])+1))
		return;
}

void aes_encrypt_ctr(aes_context_t* ctx, const u8* in, u8* out, u32 len, const u8* ivec)
{
	u32 i = 0;
	u8  ec[AES_BLOCK_SIZE];
	u8  iv[AES_BLOCK_SIZE];

	memcpy(iv, ivec, sizeof(iv));

	while (len--) {
		if (i == 0) {
			aes_encrypt(ctx, iv, ec);
			aes_ctr128_inc(iv);
		}
		*(out++) = *(in++) ^ ec[i];
		i = (i+1) % AES_BLOCK_SIZE;
	}
}