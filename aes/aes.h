#ifndef _AES_
#define _AES_

#define AES_KEY_SIZE   256
#define AES_BLOCK_SIZE 16
#define ROUNDS         14

typedef align16 struct {
	align16 u32 te32[256];
	align16 u32 td32[256];
	align16 u32 ekey[4*(ROUNDS + 1)];
	align16 u32 dkey[4*(ROUNDS + 1)];
	align16 u8  te[256]; //s-box
	align16 u8  td[256]; //inverse s-box
} aes_context_t;

void aes_encrypt(aes_context_t* ctx, const u8* in, u8* out);
void aes_decrypt(aes_context_t* ctx, const u8* in, u8* out);
void aes_set_key(aes_context_t* ctx, u8* key);
void aes_init(aes_context_t* ctx);
void aes_encrypt_ctr(aes_context_t* ctx, const u8* in, u8* out, u32 len, const u8* ivec);
#define aes_decrypt_ctr aes_encrypt_ctr

#endif /* _AES_ */