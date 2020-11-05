#include <string.h>
#include <stdio.h>
#include <stdint.h>

#define U8TO32(p)					\
  (((uint32_t)((p)[0]) << 24) | ((uint32_t)((p)[1]) << 16) |	\
   ((uint32_t)((p)[2]) <<  8) | ((uint32_t)((p)[3])      ))
#define U32TO8(p, v)					\
  (p)[0] = (uint8_t)((v) >> 24); (p)[1] = (uint8_t)((v) >> 16);	\
  (p)[2] = (uint8_t)((v) >>  8); (p)[3] = (uint8_t)((v)      ); 

typedef struct  { 
  uint32_t h[8], s[4], t[2];
  int buflen, nullt;
  uint8_t  buf[64];
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
  { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8 }};

const uint32_t cst[16] = {
  0x243F6A88,0x85A308D3,0x13198A2E,0x03707344,
  0xA4093822,0x299F31D0,0x082EFA98,0xEC4E6C89,
  0x452821E6,0x38D01377,0xBE5466CF,0x34E90C6C,
  0xC0AC29B7,0xC97C50DD,0x3F84D5B5,0xB5470917};

const uint8_t padding[] =
  {0x80,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
   0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};


void blake224_compress( state *S, const uint8_t *block ) {

  uint32_t v[16], m[16], i;
#define ROT(x,n) (((x)<<(32-n))|( (x)>>(n)))
#define G(a,b,c,d,e)					\
  v[a] += (m[sigma[i][e]] ^ cst[sigma[i][e+1]]) + v[b];	\
  v[d] = ROT( v[d] ^ v[a],16);				\
  v[c] += v[d];						\
  v[b] = ROT( v[b] ^ v[c],12);				\
  v[a] += (m[sigma[i][e+1]] ^ cst[sigma[i][e]])+v[b];	\
  v[d] = ROT( v[d] ^ v[a], 8);				\
  v[c] += v[d];						\
  v[b] = ROT( v[b] ^ v[c], 7);				
							
  for(i=0; i<16;++i)  m[i] = U8TO32(block + i*4);
  for(i=0; i< 8;++i)  v[i] = S->h[i];
  v[ 8] = S->s[0] ^ 0x243F6A88;
  v[ 9] = S->s[1] ^ 0x85A308D3;
  v[10] = S->s[2] ^ 0x13198A2E;
  v[11] = S->s[3] ^ 0x03707344;
  v[12] =  0xA4093822;
  v[13] =  0x299F31D0;
  v[14] =  0x082EFA98;
  v[15] =  0xEC4E6C89;
  if (S->nullt == 0) { 
    v[12] ^= S->t[0];
    v[13] ^= S->t[0];
    v[14] ^= S->t[1];
    v[15] ^= S->t[1];
  }

  for(i=0; i<14; ++i) {
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


void blake224_init( state *S ) {
  
  S->h[0]=0xC1059ED8;
  S->h[1]=0x367CD507;
  S->h[2]=0x3070DD17;
  S->h[3]=0xF70E5939;
  S->h[4]=0xFFC00B31;
  S->h[5]=0x68581511;
  S->h[6]=0x64F98FA7;
  S->h[7]=0xBEFA4FA4;
  S->t[0]=S->t[1]=S->buflen=S->nullt=0;
  S->s[0]=S->s[1]=S->s[2]=S->s[3] =0;
}


void blake224_update( state *S, const uint8_t *data, uint64_t datalen ) {

  int left=S->buflen >> 3; 
  int fill=64 - left;
    
  if( left && ( ((datalen >> 3) & 0x3F) >= (unsigned)fill ) ) {
    memcpy( (void*) (S->buf + left), (void*) data, fill );
    S->t[0] += 512;
    if (S->t[0] == 0) S->t[1]++;      
    blake224_compress( S, S->buf );
    data += fill;
    datalen  -= (fill << 3);       
    left = 0;
  }

  while( datalen >= 512 ) {
    S->t[0] += 512;
    if (S->t[0] == 0) S->t[1]++;
    blake224_compress( S, data );
    data += 64;
    datalen  -= 512;
  }
  
  if( datalen > 0 ) {
    memcpy( (void*) (S->buf + left), (void*) data, datalen>>3 );
    S->buflen = (left<<3) + datalen;
  }
  else S->buflen=0;
}


void blake224_final( state *S, uint8_t *digest ) {
  
  uint8_t msglen[8], zz=0x0, oz=0x80;
  uint32_t lo=S->t[0] + S->buflen, hi=S->t[1];
  if ( lo < (unsigned)S->buflen ) hi++;
  U32TO8(  msglen + 0, hi );
  U32TO8(  msglen + 4, lo );

  if ( S->buflen == 440 ) { /* one padding byte */
    S->t[0] -= 8;
    blake224_update( S, &oz, 8 );
  }
  else {
    if ( S->buflen < 440 ) { /* enough space to fill the block  */
      if ( !S->buflen ) S->nullt=1;
      S->t[0] -= 440 - S->buflen;
      blake224_update( S, padding, 440 - S->buflen );
    }
    else { /* need 2 compressions */
      S->t[0] -= 512 - S->buflen; 
      blake224_update( S, padding, 512 - S->buflen );
      S->t[0] -= 440;
      blake224_update( S, padding+1, 440 );
      S->nullt = 1;
    }
    blake224_update( S, &zz, 8 );
    S->t[0] -= 8;
  }
  S->t[0] -= 64;
  blake224_update( S, msglen, 64 );    
  
  U32TO8( digest + 0, S->h[0]);
  U32TO8( digest + 4, S->h[1]);
  U32TO8( digest + 8, S->h[2]);
  U32TO8( digest +12, S->h[3]);
  U32TO8( digest +16, S->h[4]);
  U32TO8( digest +20, S->h[5]);
  U32TO8( digest +24, S->h[6]);
}


void blake224_hash( uint8_t *out, const uint8_t *in, uint64_t inlen ) {

  state S;  
  blake224_init( &S );
  blake224_update( &S, in, inlen*8 );
  blake224_final( &S, out );
}


int main() {

  int i, v;
  uint8_t data[72], digest[28];
  uint8_t test1[]= {0x45, 0x04, 0xCB, 0x03, 0x14, 0xFB, 0x2A, 0x4F, 0x7A, 0x69, 0x2E, 0x69, 0x6E, 0x48, 0x79, 0x12, 
	       0xFE, 0x3F, 0x24, 0x68, 0xFE, 0x31, 0x2C, 0x73, 0xA5, 0x27, 0x8E, 0xC5};
  uint8_t test2[]= {0xF5, 0xAA, 0x00, 0xDD, 0x1C, 0xB8, 0x47, 0xE3, 0x14, 0x03, 0x72, 0xAF, 0x7B, 0x5C, 0x46, 0xB4, 
	       0x88, 0x8D, 0x82, 0xC8, 0xC0, 0xA9, 0x17, 0x91, 0x3C, 0xFB, 0x5D, 0x04};

  for(i=0; i<72; ++i) data[i]=0;  

  blake224_hash( digest, data, 1 );    
  v=0;
  for(i=0; i<28; ++i) {
    printf("%02X", digest[i]);
    if ( digest[i] != test1[i]) v=1;
  }
  if (v) printf("\nerror\n");
  else printf("\nok\n");

  for(i=0; i<72; ++i) data[i]=0;  

  blake224_hash( digest, data, 72 );    
  v=0;
  for(i=0; i<28; ++i) {
    printf("%02X", digest[i]);
    if ( digest[i] != test2[i]) v=1;
  }
  if (v) printf("\nerror\n");
  else printf("\nok\n");

  return 0;
}

