#include "defines.h"
#include "aes.h"
/*
static char s_key[32] = {
	0xa1, 0x6d, 0xe9, 0xcd, 0x30, 0xc8, 0x3f, 0x6c, 
	0xeb, 0x82, 0xf2, 0xfa, 0xd9, 0x8e, 0x9b, 0x77, 
	0x21, 0xc9, 0xa9, 0x38, 0xc6, 0xb5, 0xaf, 0x1c, 
	0xbb, 0xc3, 0xea, 0x92, 0x70, 0x97, 0x99, 0xcc
};

static char s_iv[16] = {
	0x00, 0x02, 0x13, 0x12, 0x01, 0x03, 0x55, 0x87, 
	0xbb, 0xc3, 0xea, 0x11, 0x7f, 0x23, 0x12, 0xdd
};


static char s_in[16]  = "attack at down!!";
static char s_enc[16] = {0};
static char s_dec[16] = {0};

static char s_crt_in[] = "This is secret messages! ;)";
static char s_crt_enc[32] = {0};
static char s_crt_dec[32] = {0};
*/
/*
############################################################## 
Block Cipher Modes of Operation Counter (CTR) 

Initial Counter is
F0F1F2F3 F4F5F6F7 F8F9FAFB FCFDFEFF

Plaintext is 
6BC1BEE2 2E409F96 E93D7E11 7393172A
AE2D8A57 1E03AC9C 9EB76FAC 45AF8E51
30C81C46 A35CE411 E5FBC119 1A0A52EF
F69F2445 DF4F9B17 AD2B417B E66C3710

Key is
603DEB10 15CA71BE 2B73AEF0 857D7781
1F352C07 3B6108D7 2D9810A3 0914DFF4

Ciphertext is 
601EC313 775789A5 B7A7F504 BBF3D228 
F443E3CA 4D62B59A CA84E990 CACAF5C5 
2B0930DA A23DE94C E87017BA 2D84988D 
DFC9C58D B67AADA6 13C2DD08 457941A6
##############################################################
*/
/*
static u32 s_in[16] = {
	0x601EC313, 0x775789A5, 0xB7A7F504, 0xBBF3D228, 
	0xF443E3CA, 0x4D62B59A, 0xCA84E990, 0xCACAF5C5, 
	0x2B0930DA, 0xA23DE94C, 0xE87017BA, 0x2D84988D, 
	0xDFC9C58D, 0xB67AADA6, 0x13C2DD08, 0x457941A6
};

static u32 s_enc[16] = {0};
static u32 s_dec[16] = {0};

static u32 s_key[8] = {
	0x603DEB10, 0x15CA71BE, 0x2B73AEF0, 0x857D7781,
	0x1F352C07, 0x3B6108D7, 0x2D9810A3, 0x0914DFF4
};

static u32 s_iv[4] = {
	0xF0F1F2F3, 0xF4F5F6F7, 0xF8F9FAFB, 0xFCFDFEFF
};
*/

static u8 s_in[64] = {
	0x60, 0x1E, 0xC3, 0x13, 0x77, 0x57, 0x89, 0xA5, 0xB7, 0xA7, 0xF5, 0x04, 0xBB, 0xF3, 0xD2, 0x28, 
	0xF4, 0x43, 0xE3, 0xCA, 0x4D, 0x62, 0xB5, 0x9A, 0xCA, 0x84, 0xE9, 0x90, 0xCA, 0xCA, 0xF5, 0xC5, 
	0x2B, 0x09, 0x30, 0xDA, 0xA2, 0x3D, 0xE9, 0x4C, 0xE8, 0x70, 0x17, 0xBA, 0x2D, 0x84, 0x98, 0x8D, 
	0xDF, 0xC9, 0xC5, 0x8D, 0xB6, 0x7A, 0xAD, 0xA6, 0x13, 0xC2, 0xDD, 0x08, 0x45, 0x79, 0x41, 0xA6
};

static u8 s_enc[64] = {0};
static u8 s_dec[64] = {0};

static u8 s_key[32] = {
	0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
	0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4
};

static u8 s_iv[16] = {
	0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
};

int main(int argc, char* argv[])
{
	aes_context_t aes_ctx;
	aes_init(&aes_ctx);
	aes_set_key(&aes_ctx, s_key);
	//aes_encrypt(&aes_ctx, s_in, s_enc);
	//aes_decrypt(&aes_ctx, s_enc, s_dec);
	aes_encrypt_ctr(&aes_ctx, s_in, s_enc, sizeof(s_in), s_iv);
	aes_decrypt_ctr(&aes_ctx, s_enc, s_dec, sizeof(s_in), s_iv);
	return 0;
}