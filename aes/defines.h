#ifndef _DEFINES_
#define _DEFINES_

typedef unsigned __int64 u64;
typedef unsigned long    u32;
typedef unsigned short   u16;
typedef unsigned char    u8;

typedef __int64 s64;
typedef long    s32;
typedef short   s16;
typedef char    s8;

#define d8(_x)  ((u8)(_x))
#define d16(_x) ((u16)(_x))
#define d32(_x) ((u32)(_x))
#define d64(_x) ((u64)(_x))
#define dSZ(_x) ((size_t)(_x))

#define bswap16(x) _byteswap_ushort(x)
#define bswap32(x) _byteswap_ulong(x)
#define bswap64(x) _byteswap_uint64(x)

#define ror64(x,y)     (_rotr64((x),(y)))
#define rol64(x,y)     (_rotl64((x),(y)))
#define rol32(x,y)     (_rotl((x), (y)))
#define ror32(x,y)     (_rotr((x), (y)))

#define align16  __declspec(align(16))

#define p8(_x)   ((u8*)(_x))
#define p16(_x)  ((u16*)(_x))
#define p32(_x)  ((u32*)(_x))
#define p64(_x)  ((u64*)(_x))
#define pv(_x)   ((void*)(_x))
#define ppv(_x)  ((void**)(_x)) 

#endif
