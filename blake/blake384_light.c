#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define U8TO32(p) \
  (((uint32_t)((p)[0]) << 24) | ((uint32_t)((p)[1]) << 16) | \
   ((uint32_t)((p)[2]) <<  8) | ((uint32_t)((p)[3])      ))
#define U8TO64(p) \
  (((uint64_t)U8TO32(p) << 32) | (uint64_t)U8TO32((p) + 4))
#define U32TO8(p, v) \
    (p)[0] = (uint8_t)((v) >> 24); (p)[1] = (uint8_t)((v) >> 16); \
    (p)[2] = (uint8_t)((v) >>  8); (p)[3] = (uint8_t)((v)      ); 
#define U64TO8(p, v) \
    U32TO8((p),     (uint32_t)((v) >> 32));	\
    U32TO8((p) + 4, (uint32_t)((v)      )); 

typedef struct  { 
  uint64_t h[8], s[4], t[2];
  int buflen, nullt;
  uint8_t buf[128];
} state;

const uint8_t sigma[][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 },
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8 },
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13 },
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9 },
    {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11 },
    {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10 },
    { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5 },
    {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13 ,0 },
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 },
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8 },
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13 },
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9 }};

const uint64_t cst[16] = {
  0x243F6A8885A308D3ULL,0x13198A2E03707344ULL,0xA4093822299F31D0ULL,0x082EFA98EC4E6C89ULL,
  0x452821E638D01377ULL,0xBE5466CF34E90C6CULL,0xC0AC29B7C97C50DDULL,0x3F84D5B5B5470917ULL,
  0x9216D5D98979FB1BULL,0xD1310BA698DFB5ACULL,0x2FFD72DBD01ADFB7ULL,0xB8E1AFED6A267E96ULL,
  0xBA7C9045F12C7F99ULL,0x24A19947B3916CF7ULL,0x0801F2E2858EFC16ULL,0x636920D871574E69ULL
};

static const uint8_t padding[129] =
  { 0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};


void blake384_compress( state * S, const uint8_t * block ) {

  uint64_t v[16], m[16], i;
#define ROT(x,n) (((x)<<(64-n))|( (x)>>(n)))
#define G(a,b,c,d,e)					\
  v[a] += (m[sigma[i][e]] ^ cst[sigma[i][e+1]]) + v[b];	\
  v[d] = ROT( v[d] ^ v[a],32);				\
  v[c] += v[d];						\
  v[b] = ROT( v[b] ^ v[c],25);				\
  v[a] += (m[sigma[i][e+1]] ^ cst[sigma[i][e]])+v[b];	\
  v[d] = ROT( v[d] ^ v[a],16);				\
  v[c] += v[d];						\
  v[b] = ROT( v[b] ^ v[c],11);				

  for(i=0; i<16;++i)  m[i] = U8TO64(block + i*8);
  for(i=0; i< 8;++i)  v[i] = S->h[i];
  v[ 8] = S->s[0] ^ 0x243F6A8885A308D3ULL;
  v[ 9] = S->s[1] ^ 0x13198A2E03707344ULL;
  v[10] = S->s[2] ^ 0xA4093822299F31D0ULL;
  v[11] = S->s[3] ^ 0x082EFA98EC4E6C89ULL;
  v[12] =  0x452821E638D01377ULL;
  v[13] =  0xBE5466CF34E90C6CULL;
  v[14] =  0xC0AC29B7C97C50DDULL;
  v[15] =  0x3F84D5B5B5470917ULL;
  if (S->nullt == 0) { 
    v[12] ^= S->t[0];
    v[13] ^= S->t[0];
    v[14] ^= S->t[1];
    v[15] ^= S->t[1];
  }

  for(i=0; i<16; ++i) {
    G( 0, 4, 8,12, 0);
    G( 1, 5, 9,13, 2);
    G( 2, 6,10,14, 4);
    G( 3, 7,11,15, 6);
    G( 3, 4, 9,14,14);   
    G( 2, 7, 8,13,12);
    G( 0, 5,10,15, 8);
    G( 1, 6,11,12,10);
  }

  for(i=0; i<16;++i)  S->h[i%8] ^= v[i];
  for(i=0; i<8 ;++i)  S->h[i] ^= S->s[i%4];
}


void blake384_init( state * S ) {

  S->h[0]=0xCBBB9D5DC1059ED8ULL;
  S->h[1]=0x629A292A367CD507ULL;
  S->h[2]=0x9159015A3070DD17ULL;
  S->h[3]=0x152FECD8F70E5939ULL;
  S->h[4]=0x67332667FFC00B31ULL;
  S->h[5]=0x8EB44A8768581511ULL;
  S->h[6]=0xDB0C2E0D64F98FA7ULL;
  S->h[7]=0x47B5481DBEFA4FA4ULL;
  S->t[0]=S->t[1]=S->buflen=S->nullt=0;
  S->s[0]=S->s[1]=S->s[2]=S->s[3] =0;
}


void blake384_update( state * S, const uint8_t * data, uint64_t datalen ) {


  int left = (S->buflen >> 3); 
  int fill = 128 - left;

  if( left && ( ((datalen >> 3) & 0x7F) >= (unsigned)fill ) ) {
    memcpy( (void *) (S->buf + left), (void *) data, fill );
    S->t[0] += 1024;
    blake384_compress( S, S->buf );
    data += fill;
    datalen  -= (fill << 3);       
    left = 0;
  }

  while( datalen >= 1024 ) {  
    S->t[0] += 1024;
    blake384_compress( S, data );
    data += 128;
    datalen  -= 1024;
  }

  if( datalen > 0 ) {
    memcpy( (void *) (S->buf + left), (void *) data, ( datalen>>3 ) & 0x7F );
    S->buflen = (left<<3) + datalen;
  }
  else S->buflen=0;
}


void blake384_final( state * S, uint8_t * digest ) {

  uint8_t msglen[16], zz=0x00,oz=0x80;
  uint64_t lo=S->t[0] + S->buflen, hi = S->t[1];
  if ( lo < (unsigned)S->buflen ) hi++;
  U64TO8(  msglen + 0, hi );
  U64TO8(  msglen + 8, lo );

  if ( S->buflen == 888 ) { /* one padding byte */
    S->t[0] -= 8; 
    blake384_update( S, &oz, 8 );
  }
  else {
    if ( S->buflen < 888 ) { /* enough space to fill the block */
      if ( S->buflen == 0 ) S->nullt=1;
      S->t[0] -= 888 - S->buflen;
      blake384_update( S, padding, 888 - S->buflen );
    }
    else { /* NOT enough space, need 2 compressions */ 
      S->t[0] -= 1024 - S->buflen; 
      blake384_update( S, padding, 1024 - S->buflen );
      S->t[0] -= 888;
      blake384_update( S, padding+1, 888 );
      S->nullt = 1;
    }
    blake384_update( S, &zz, 8 );
    S->t[0] -= 8;
  }
  S->t[0] -= 128;
  blake384_update( S, msglen, 128 );    

  U64TO8( digest + 0, S->h[0]);
  U64TO8( digest + 8, S->h[1]);
  U64TO8( digest +16, S->h[2]);
  U64TO8( digest +24, S->h[3]);
  U64TO8( digest +32, S->h[4]);
  U64TO8( digest +40, S->h[5]);
}


void blake384_hash( uint8_t *out, const uint8_t *in, uint64_t inlen ) {

  state S;
  blake384_init( &S );
  blake384_update( &S, in, inlen*8 );
  blake384_final( &S, out );
}


int main() {

  int i, v;
  uint8_t data[144], digest[48];
  uint8_t test1[]= {0x10, 0x28, 0x1F, 0x67, 0xE1, 0x35, 0xE9, 0x0A, 0xE8, 0xE8, 0x82, 0x25, 0x1A, 0x35, 0x55, 0x10, 
	       0xA7, 0x19, 0x36, 0x7A, 0xD7, 0x02, 0x27, 0xB1, 0x37, 0x34, 0x3E, 0x1B, 0xC1, 0x22, 0x01, 0x5C, 
	       0x29, 0x39, 0x1E, 0x85, 0x45, 0xB5, 0x27, 0x2D, 0x13, 0xA7, 0xC2, 0x87, 0x9D, 0xA3, 0xD8, 0x07};
  uint8_t test2[]= {0x0B, 0x98, 0x45, 0xDD, 0x42, 0x95, 0x66, 0xCD, 0xAB, 0x77, 0x2B, 0xA1, 0x95, 0xD2, 0x71, 0xEF, 
	       0xFE, 0x2D, 0x02, 0x11, 0xF1, 0x69, 0x91, 0xD7, 0x66, 0xBA, 0x74, 0x94, 0x47, 0xC5, 0xCD, 0xE5, 
	       0x69, 0x78, 0x0B, 0x2D, 0xAA, 0x66, 0xC4, 0xB2, 0x24, 0xA2, 0xEC, 0x2E, 0x5D, 0x09, 0x17, 0x4C}; 

  for(i=0; i<144; ++i) data[i]=0;  

  blake384_hash( digest, data, 1 );    
  v=0;
  for(i=0; i<48; ++i) {
    printf("%02X", digest[i]);
    if ( digest[i] != test1[i]) v=1;
  }
  if (v) printf("\nerror\n");
  else  printf("\nok\n");

  for(i=0; i<144; ++i) data[i]=0;  

  blake384_hash( digest, data, 144 );    
  v=0;
  for(i=0; i<48; ++i) {
    printf("%02X", digest[i]);
    if ( digest[i] != test2[i]) v=1;
  }
  if (v) printf("\nerror\n");
  else printf("\nok\n");

  return 0;
}

