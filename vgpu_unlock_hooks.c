/*
 * vGPU unlock hooks.
 *
 * This file is designed to be included into a single translation unit of the
 * vGPU driver's kernel module. It hooks the nv_ioremap_* functions and memcpy
 * for that translation unit and applies the vgpu_unlock patch when the magic
 * and key values has been accessed by the driver.
 *
 * Copyright 2021 Jonathan Johansson
 * This file is part of the "vgpu_unlock" project, and is distributed under the
 * MIT License. See the LICENSE file for more details.
 * 
 * Contributions from Krutav Shah and the vGPU Unlocking community included :)
 * 
 */

/*------------------------------------------------------------------------------
 * Implementation of AES128-ECB.
 *------------------------------------------------------------------------------
 */

typedef struct 
{
	uint8_t round_key[176];
}
vgpu_unlock_aes128_ctx;

typedef uint8_t vgpu_unlock_aes128_state[4][4];

#define Nb 4
#define Nk 4
#define Nr 10
#define getSBoxValue(num) (vgpu_unlock_aes128_sbox[(num)])
#define getSBoxInvert(num) (vgpu_unlock_aes128_rsbox[(num)])
#define Multiply(x, y)                                                                                                            \
	(  ((y & 1) * x) ^                                                                                                        \
	((y>>1 & 1) * vgpu_unlock_aes128_xtime(x)) ^                                                                              \
	((y>>2 & 1) * vgpu_unlock_aes128_xtime(vgpu_unlock_aes128_xtime(x))) ^                                                    \
	((y>>3 & 1) * vgpu_unlock_aes128_xtime(vgpu_unlock_aes128_xtime(vgpu_unlock_aes128_xtime(x)))) ^                          \
	((y>>4 & 1) * vgpu_unlock_aes128_xtime(vgpu_unlock_aes128_xtime(vgpu_unlock_aes128_xtime(vgpu_unlock_aes128_xtime(x)))))) \

static const uint8_t vgpu_unlock_aes128_sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

static const uint8_t vgpu_unlock_aes128_rsbox[256] = {
  0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
  0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
  0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
  0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
  0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
  0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
  0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
  0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
  0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
  0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
  0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
  0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
  0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
  0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
  0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d };

static const uint8_t vgpu_unlock_aes128_rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36 };

static void vgpu_unlock_aes128_key_expansion(uint8_t *round_key,
                                             const uint8_t *Key)
{
	unsigned i, j, k;
	uint8_t tempa[4];
  
	for (i = 0; i < Nk; ++i)
	{
		round_key[(i * 4) + 0] = Key[(i * 4) + 0];
		round_key[(i * 4) + 1] = Key[(i * 4) + 1];
		round_key[(i * 4) + 2] = Key[(i * 4) + 2];
		round_key[(i * 4) + 3] = Key[(i * 4) + 3];
	}

	for (i = Nk; i < Nb * (Nr + 1); ++i)
	{
		k = (i - 1) * 4;
		tempa[0] = round_key[k + 0];
		tempa[1] = round_key[k + 1];
		tempa[2] = round_key[k + 2];
		tempa[3] = round_key[k + 3];

		if (i % Nk == 0)
		{
			const uint8_t u8tmp = tempa[0];
			tempa[0] = tempa[1];
			tempa[1] = tempa[2];
			tempa[2] = tempa[3];
			tempa[3] = u8tmp;
			tempa[0] = getSBoxValue(tempa[0]);
			tempa[1] = getSBoxValue(tempa[1]);
			tempa[2] = getSBoxValue(tempa[2]);
			tempa[3] = getSBoxValue(tempa[3]);
			tempa[0] = tempa[0] ^ vgpu_unlock_aes128_rcon[i/Nk];
		}

		j = i * 4; k=(i - Nk) * 4;
		round_key[j + 0] = round_key[k + 0] ^ tempa[0];
		round_key[j + 1] = round_key[k + 1] ^ tempa[1];
		round_key[j + 2] = round_key[k + 2] ^ tempa[2];
		round_key[j + 3] = round_key[k + 3] ^ tempa[3];
	}
}

static void vgpu_unlock_aes128_add_round_key(uint8_t round,
                                             vgpu_unlock_aes128_state *state,
                                             const uint8_t *round_key)
{
	uint8_t i,j;

	for (i = 0; i < 4; ++i)
	{
		for (j = 0; j < 4; ++j)
		{
			(*state)[i][j] ^= round_key[(round * Nb * 4) + (i * Nb) + j];
		}
	}
}

static void vgpu_unlock_aes128_sub_bytes(vgpu_unlock_aes128_state *state)
{
	uint8_t i, j;

	for (i = 0; i < 4; ++i)
	{
		for (j = 0; j < 4; ++j)
		{
			(*state)[j][i] = getSBoxValue((*state)[j][i]);
		}
	}
}

static void vgpu_unlock_aes128_shift_rows(vgpu_unlock_aes128_state *state)
{
	uint8_t temp;

	temp           = (*state)[0][1];
	(*state)[0][1] = (*state)[1][1];
	(*state)[1][1] = (*state)[2][1];
	(*state)[2][1] = (*state)[3][1];
	(*state)[3][1] = temp;

	temp           = (*state)[0][2];
	(*state)[0][2] = (*state)[2][2];
	(*state)[2][2] = temp;

	temp           = (*state)[1][2];
	(*state)[1][2] = (*state)[3][2];
	(*state)[3][2] = temp;

	temp           = (*state)[0][3];
	(*state)[0][3] = (*state)[3][3];
	(*state)[3][3] = (*state)[2][3];
	(*state)[2][3] = (*state)[1][3];
	(*state)[1][3] = temp;
}

static uint8_t vgpu_unlock_aes128_xtime(uint8_t x)
{
	return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

static void vgpu_unlock_aes128_mix_columns(vgpu_unlock_aes128_state *state)
{
	uint8_t i;
	uint8_t tmp, tm, t;

	for (i = 0; i < 4; ++i)
	{  
		t   = (*state)[i][0];
	  	tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3];
	  	tm  = (*state)[i][0] ^ (*state)[i][1];
		tm = vgpu_unlock_aes128_xtime(tm);  (*state)[i][0] ^= tm ^ tmp;
	  	tm  = (*state)[i][1] ^ (*state)[i][2];
		tm = vgpu_unlock_aes128_xtime(tm);  (*state)[i][1] ^= tm ^ tmp;
	  	tm  = (*state)[i][2] ^ (*state)[i][3];
		tm = vgpu_unlock_aes128_xtime(tm);  (*state)[i][2] ^= tm ^ tmp;
	  	tm  = (*state)[i][3] ^ t;
		tm = vgpu_unlock_aes128_xtime(tm);  (*state)[i][3] ^= tm ^ tmp;
	}
}

static void vgpu_unlock_aes128_inv_mix_columns(vgpu_unlock_aes128_state *state)
{
	int i;
	uint8_t a, b, c, d;

	for (i = 0; i < 4; ++i)
	{ 
		a = (*state)[i][0];
		b = (*state)[i][1];
		c = (*state)[i][2];
		d = (*state)[i][3];

		(*state)[i][0] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
		(*state)[i][1] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
		(*state)[i][2] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
		(*state)[i][3] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
	}
}

static void vgpu_unlock_aes128_inv_sub_bytes(vgpu_unlock_aes128_state *state)
{
	uint8_t i, j;

	for (i = 0; i < 4; ++i)
	{
		for (j = 0; j < 4; ++j)
		{
			(*state)[j][i] = getSBoxInvert((*state)[j][i]);
		}
	}
}

static void vgpu_unlock_aes128_inv_shift_rows(vgpu_unlock_aes128_state *state)
{
	uint8_t temp;

	temp = (*state)[3][1];
	(*state)[3][1] = (*state)[2][1];
	(*state)[2][1] = (*state)[1][1];
	(*state)[1][1] = (*state)[0][1];
	(*state)[0][1] = temp;

	temp = (*state)[0][2];
	(*state)[0][2] = (*state)[2][2];
	(*state)[2][2] = temp;

	temp = (*state)[1][2];
	(*state)[1][2] = (*state)[3][2];
	(*state)[3][2] = temp;

	temp = (*state)[0][3];
	(*state)[0][3] = (*state)[1][3];
	(*state)[1][3] = (*state)[2][3];
	(*state)[2][3] = (*state)[3][3];
	(*state)[3][3] = temp;
}

static void vgpu_unlock_aes128_cipher(vgpu_unlock_aes128_state *state,
                                      const uint8_t* round_key)
{
	uint8_t round = 0;

	vgpu_unlock_aes128_add_round_key(0, state, round_key);

	for (round = 1; ; ++round)
	{
		vgpu_unlock_aes128_sub_bytes(state);
		vgpu_unlock_aes128_shift_rows(state);

		if (round == Nr)
		{
			break;
		}

		vgpu_unlock_aes128_mix_columns(state);
		vgpu_unlock_aes128_add_round_key(round, state, round_key);
	}

	vgpu_unlock_aes128_add_round_key(Nr, state, round_key);
}

static void vgpu_unlock_aes128_inv_cipher(vgpu_unlock_aes128_state *state,
                                          const uint8_t* round_key)
{
	uint8_t round = 0;

	vgpu_unlock_aes128_add_round_key(Nr, state, round_key);

	for (round = (Nr - 1); ; --round)
	{
		vgpu_unlock_aes128_inv_shift_rows(state);
		vgpu_unlock_aes128_inv_sub_bytes(state);
		vgpu_unlock_aes128_add_round_key(round, state, round_key);

		if (round == 0)
		{
			break;
		}

		vgpu_unlock_aes128_inv_mix_columns(state);
	}
}

static void vgpu_unlock_aes128_init(vgpu_unlock_aes128_ctx *ctx,
                                    const uint8_t *key)
{
	vgpu_unlock_aes128_key_expansion(ctx->round_key, key);
}

static void vgpu_unlock_aes128_encrypt(const vgpu_unlock_aes128_ctx *ctx,
                                       uint8_t *buf)
{
	vgpu_unlock_aes128_cipher((vgpu_unlock_aes128_state*)buf,
	                          ctx->round_key);
}

static void vgpu_unlock_aes128_decrypt(const vgpu_unlock_aes128_ctx *ctx,
                                       uint8_t* buf)
{
	vgpu_unlock_aes128_inv_cipher((vgpu_unlock_aes128_state*)buf,
	                              ctx->round_key);
}

#undef Nb
#undef Nk
#undef Nr
#undef getSBoxValue
#undef getSBoxInvert
#undef Multiply

/*------------------------------------------------------------------------------
 * End of AES128-ECB implementation.
 *------------------------------------------------------------------------------
 */

/*------------------------------------------------------------------------------
 * Implementation of SHA256.
 * Original author: Brad Conte (brad AT bradconte.com)
 *------------------------------------------------------------------------------
 */

typedef struct {
	uint8_t data[64];
	uint32_t datalen;
	uint64_t bitlen;
	uint32_t state[8];
}
vgpu_unlock_sha256_ctx;

#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static void vgpu_unlock_sha256_transform(vgpu_unlock_sha256_ctx *ctx,
                                         const uint8_t data[])
{
	static const uint32_t k[64] = {
		0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
		0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
		0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
		0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
		0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
		0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
		0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
		0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
	};

	uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for ( ; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a,b,c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

static void vgpu_unlock_sha256_init(vgpu_unlock_sha256_ctx *ctx)
{
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

static void vgpu_unlock_sha256_update(vgpu_unlock_sha256_ctx *ctx,
                                      const uint8_t data[],
                                      size_t len)
{
	uint32_t i;

	for (i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			vgpu_unlock_sha256_transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}

static void vgpu_unlock_sha256_final(vgpu_unlock_sha256_ctx *ctx,
                                     uint8_t hash[])
{
	uint32_t i;

	i = ctx->datalen;

	/* Pad whatever data is left in the buffer. */
	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0x00;
	}
	else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0x00;
		vgpu_unlock_sha256_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}

	/*
	 * Append to the padding the total message's length in bits and
	 * transform.
	 */
	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	vgpu_unlock_sha256_transform(ctx, ctx->data);

	/*
	 * Since this implementation uses little endian byte ordering and SHA
	 * uses big endian, reverse all the bytes when copying the final state
	 * to the output hash.
	 */
	for (i = 0; i < 4; ++i) {
		hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}

#undef ROTLEFT
#undef ROTRIGHT

#undef CH
#undef MAJ
#undef EP0
#undef EP1
#undef SIG0
#undef SIG1

/*------------------------------------------------------------------------------
 * End of SHA256 implementation.
 *------------------------------------------------------------------------------
 */


/*------------------------------------------------------------------------------
 * Implementation of HMAC-SHA256.
 *------------------------------------------------------------------------------
 */

static void vgpu_unlock_hmac_sha256(void* dst,
                                    const void *msg,
                                    size_t msg_size,
                                    const void *key,
                                    size_t key_size)
{
	vgpu_unlock_sha256_ctx ctx;
	uint8_t o_key[96];
	uint8_t i_key_pad[64];
	uint8_t i;

	for (i = 0; i < 64; i++)
	{
		if (i < key_size)
		{
			o_key[i] = ((uint8_t*)key)[i] ^ 0x5c;
			i_key_pad[i] = ((uint8_t*)key)[i] ^ 0x36;
		}
		else
		{
			o_key[i] = 0x5c;
			i_key_pad[i] = 0x36;
		}
	}

	vgpu_unlock_sha256_init(&ctx);
	vgpu_unlock_sha256_update(&ctx, i_key_pad, sizeof(i_key_pad));
	vgpu_unlock_sha256_update(&ctx, msg, msg_size);
	vgpu_unlock_sha256_final(&ctx, &o_key[64]);

	vgpu_unlock_sha256_init(&ctx);
	vgpu_unlock_sha256_update(&ctx, o_key, sizeof(o_key));
	vgpu_unlock_sha256_final(&ctx, dst);
}

/*------------------------------------------------------------------------------
 * End of HMAC-SHA256 implementation.
 *------------------------------------------------------------------------------
 */

/*------------------------------------------------------------------------------
 * Implementation of vgpu_unlock hooks.
 *------------------------------------------------------------------------------
 */

/* Debug logs can be enabled here. To enable it, change 0 to 1. */
#if 0
	#define LOG(...) printk(__VA_ARGS__)
#else
	#define LOG(...)
#endif

typedef struct {
	uint8_t num_blocks; /* Number of 16 byte blocks up to 'sign'. */
	uint8_t name1_len; /* Length of first name (unused?) */
	uint8_t name2_len; /* Length of second name (used by VM) */
	uint16_t dev_id;
	uint16_t vend_id; /* Check skipped if zero. */
	uint16_t subsys_id;
	uint16_t subsys_vend_id; /* Check skipped if zero. */
	char name1_2[38]; /* First and second name, no separation. */
	uint8_t sign[0x20];
}
__attribute__((packed))
vgpu_unlock_vgpu_t;

/* Helper macro to initialize the structure above. */
#define VGPU(dev_id, subsys_id, name, len) \
	{ (10 + 2 * len + 15) / 16,          /* num_blocks */     \
	  len,                               /* name1_len */      \
	  len,                               /* name2_len */      \
	  (dev_id),                          /* dev_id */         \
	  0,                                 /* vend_id */        \
	  (subsys_id),                       /* subsys_id */      \
	  0,                                 /* subsys_vend_id */ \
	  { name name } }                    /* name1_2 */

static vgpu_unlock_vgpu_t vgpu_unlock_vgpu[] =
{
	/* Tesla M10 (Maxwell) */
	VGPU(0x13bd, 0x11cc, "GRID M10-0B",11),
	VGPU(0x13bd, 0x11cd, "GRID M10-1B",11),
	VGPU(0x13bd, 0x1339, "GRID M10-1B4",12),
	VGPU(0x13bd, 0x1286, "GRID M10-2B",11),
	VGPU(0x13bd, 0x12ee, "GRID M10-2B4",12),
	VGPU(0x13bd, 0x11ce, "GRID M10-0Q",11),
	VGPU(0x13bd, 0x11cf, "GRID M10-1Q",11),
	VGPU(0x13bd, 0x11d0, "GRID M10-2Q",11),
	VGPU(0x13bd, 0x11d1, "GRID M10-4Q",11),
	VGPU(0x13bd, 0x11d2, "GRID M10-8Q",11),
	VGPU(0x13bd, 0x11d3, "GRID M10-1A",11),
	VGPU(0x13bd, 0x11d4, "GRID M10-2A",11),
	VGPU(0x13bd, 0x11d5, "GRID M10-4A",11),
	VGPU(0x13bd, 0x11d6, "GRID M10-8A",11),

	/* Tesla M60 (Maxwell 2.0) */
	VGPU(0x13f2, 0x114c, "GRID M60-0Q",11),
	VGPU(0x13f2, 0x114d, "GRID M60-1Q",11),
	VGPU(0x13f2, 0x114e, "GRID M60-2Q",11),
	VGPU(0x13f2, 0x114f, "GRID M60-4Q",11),
	VGPU(0x13f2, 0x1150, "GRID M60-8Q",11),
	VGPU(0x13f2, 0x1176, "GRID M60-0B",11),
	VGPU(0x13f2, 0x1177, "GRID M60-1B",11),
	VGPU(0x13f2, 0x117D, "GRID M60-2B",11),
	VGPU(0x13f2, 0x1337, "GRID M60-1B4",12),
	VGPU(0x13f2, 0x12ec, "GRID M60-2B4",12),
	VGPU(0x13f2, 0x11ae, "GRID M60-1A",11),
	VGPU(0x13f2, 0x11aF, "GRID M60-2A",11),
	VGPU(0x13f2, 0x11b0, "GRID M60-4A",11),
	VGPU(0x13f2, 0x11b1, "GRID M60-8A",11),

	/* Tesla P4 (Pascal) */
	VGPU(0x1bb3, 0x1203, "GRID P4-1B",10),
	VGPU(0x1bb3, 0x1204, "GRID P4-1Q",10),
	VGPU(0x1bb3, 0x1205, "GRID P4-2Q",10),
	VGPU(0x1bb3, 0x1206, "GRID P4-4Q",10),
	VGPU(0x1bb3, 0x1207, "GRID P4-8Q",10),
	VGPU(0x1bb3, 0x1208, "GRID P4-1A",10),
	VGPU(0x1bb3, 0x1209, "GRID P4-2A",10),
	VGPU(0x1bb3, 0x120a, "GRID P4-4A",10),
	VGPU(0x1bb3, 0x120b, "GRID P4-8A",10),
	VGPU(0x1bb3, 0x1288, "GRID P4-2B",10),
	VGPU(0x1bb3, 0x12f1, "GRID P4-2B4",11),
	VGPU(0x1bb3, 0x133c, "GRID P4-1B4",11),
	VGPU(0x1bb3, 0x1380, "GRID P4-8C",10),
	VGPU(0x1bb3, 0x1385, "GRID P4-4C",10),

	/* Tesla P40 (Pascal) */
	VGPU(0x1b38, 0x11e7, "GRID P40-1B",11),
	VGPU(0x1b38, 0x11e8, "GRID P40-1Q",11),
	VGPU(0x1b38, 0x11e9, "GRID P40-2Q",11),
	VGPU(0x1b38, 0x11ea, "GRID P40-3Q",11),
	VGPU(0x1b38, 0x11eb, "GRID P40-4Q",11),
	VGPU(0x1b38, 0x11ec, "GRID P40-6Q",11),
	VGPU(0x1b38, 0x11ed, "GRID P40-8Q",11),
	VGPU(0x1b38, 0x11ee, "GRID P40-12Q",12),
	VGPU(0x1b38, 0x11ef, "GRID P40-24Q",12),
	VGPU(0x1b38, 0x11f0, "GRID P40-1A",11),
	VGPU(0x1b38, 0x11f1, "GRID P40-2A",11),
	VGPU(0x1b38, 0x11f2, "GRID P40-3A",11),
	VGPU(0x1b38, 0x11f3, "GRID P40-4A",11),
	VGPU(0x1b38, 0x11f4, "GRID P40-6A",11),
	VGPU(0x1b38, 0x11f5, "GRID P40-8A",11),
	VGPU(0x1b38, 0x11f6, "GRID P40-12A",12),
	VGPU(0x1b38, 0x11f7, "GRID P40-24A",12),
	VGPU(0x1b38, 0x1287, "GRID P40-2B",11),
	VGPU(0x1b38, 0x12ef, "GRID P40-2B4",12),
	VGPU(0x1b38, 0x133a, "GRID P40-1B4",12),
	VGPU(0x1b38, 0x137e, "GRID P40-24C",12),
	VGPU(0x1b38, 0x1381, "GRID P40-4C",11),
	VGPU(0x1b38, 0x1382, "GRID P40-6C",11),
	VGPU(0x1b38, 0x1383, "GRID P40-8C",11),
	VGPU(0x1b38, 0x1384, "GRID P40-12C",12),
	
	/* Tesla V100 32GB PCIE (Volta) */
	VGPU(0x1db6, 0x12bd, "GRID V100D-1B",13),
	VGPU(0x1db6, 0x12be, "GRID V100D-2B",13),
	VGPU(0x1db6, 0x12f7, "GRID V100D-2B4",14),
	VGPU(0x1db6, 0x1342, "GRID V100D-1B4",14),
	VGPU(0x1db6, 0x12bf, "GRID V100D-1Q",13),
	VGPU(0x1db6, 0x12c0, "GRID V100D-2Q",13),
	VGPU(0x1db6, 0x12c1, "GRID V100D-4Q",13),
	VGPU(0x1db6, 0x12c2, "GRID V100D-8Q",13),
	VGPU(0x1db6, 0x12c3, "GRID V100D-16Q",14),
	VGPU(0x1db6, 0x12c4, "GRID V100D-32Q",14),
	VGPU(0x1db6, 0x12c5, "GRID V100D-1A",13),
	VGPU(0x1db6, 0x12c6, "GRID V100D-2A",13),
	VGPU(0x1db6, 0x12c7, "GRID V100D-4A",13),
	VGPU(0x1db6, 0x12c8, "GRID V100D-8A",13),
	VGPU(0x1db6, 0x12c9, "GRID V100D-16A",14),
	VGPU(0x1db6, 0x12ca, "GRID V100D-32A",14),
	VGPU(0x1db6, 0x1395, "GRID V100D-4C",13),
	VGPU(0x1db6, 0x1396, "GRID V100D-8C",13),
	VGPU(0x1db6, 0x1397, "GRID V100D-16C",14),
	VGPU(0x1db6, 0x1377, "GRID V100D-32C",14),

	/* Tesla T4 (Turing) */
	VGPU(0x1eb8, 0x1309, "GRID T4-1B",10),
	VGPU(0x1eb8, 0x130a, "GRID T4-2B",10),
	VGPU(0x1eb8, 0x130b, "GRID T4-2B4",11),
	VGPU(0x1eb8, 0x130c, "GRID T4-1Q",10),
	VGPU(0x1eb8, 0x130d, "GRID T4-2Q",10),
	VGPU(0x1eb8, 0x130e, "GRID T4-4Q",10),
	VGPU(0x1eb8, 0x130f, "GRID T4-8Q",10),
	VGPU(0x1eb8, 0x1310, "GRID T4-16Q",11),
	VGPU(0x1eb8, 0x1311, "GRID T4-1A",10),
	VGPU(0x1eb8, 0x1312, "GRID T4-2A",10),
	VGPU(0x1eb8, 0x1313, "GRID T4-4A",10),
	VGPU(0x1eb8, 0x1314, "GRID T4-8A",10),
	VGPU(0x1eb8, 0x1315, "GRID T4-16A",11),
	VGPU(0x1eb8, 0x1345, "GRID T4-1B4",11),
	VGPU(0x1eb8, 0x1375, "GRID T4-16C",11),
	VGPU(0x1eb8, 0x139a, "GRID T4-4C",10),
	VGPU(0x1eb8, 0x139b, "GRID T4-8C",10),

	/* Quadro RTX 6000 (Turing) */
	VGPU(0x1e30, 0x1325, "GRID RTX6000-1Q",15),
	VGPU(0x1e30, 0x1326, "GRID RTX6000-2Q",15),
	VGPU(0x1e30, 0x1327, "GRID RTX6000-3Q",15),
	VGPU(0x1e30, 0x1328, "GRID RTX6000-4Q",15),
	VGPU(0x1e30, 0x1329, "GRID RTX6000-6Q",15),
	VGPU(0x1e30, 0x132a, "GRID RTX6000-8Q",15),
	VGPU(0x1e30, 0x132b, "GRID RTX6000-12Q",16),
	VGPU(0x1e30, 0x132c, "GRID RTX6000-24Q",16),
	VGPU(0x1e30, 0x13bf, "GRID RTX6000-4C",15),
	VGPU(0x1e30, 0x13c0, "GRID RTX6000-6C",15),
	VGPU(0x1e30, 0x13c1, "GRID RTX6000-8C",15),
	VGPU(0x1e30, 0x13c2, "GRID RTX6000-12C",16),
	VGPU(0x1e30, 0x13c3, "GRID RTX6000-24C",16),
	VGPU(0x1e30, 0x1437, "GRID RTX6000-1B",15),
	VGPU(0x1e30, 0x1438, "GRID RTX6000-2B",15),
	VGPU(0x1e30, 0x1439, "GRID RTX6000-1A",15),
	VGPU(0x1e30, 0x143a, "GRID RTX6000-2A",15),
	VGPU(0x1e30, 0x143b, "GRID RTX6000-3A",15),
	VGPU(0x1e30, 0x143c, "GRID RTX6000-4A",15),
	VGPU(0x1e30, 0x143d, "GRID RTX6000-6A",15),
	VGPU(0x1e30, 0x143e, "GRID RTX6000-8A",15),
	VGPU(0x1e30, 0x143f, "GRID RTX6000-12A",16),
	VGPU(0x1e30, 0x1440, "GRID RTX6000-24A",16),

	/* RTX A6000 (Ampere) */
	VGPU(0x2230, 0x14fa, "NVIDIA RTXA6000-1B",18),
	VGPU(0x2230, 0x14fb, "NVIDIA RTXA6000-2B",18),
	VGPU(0x2230, 0x14fc, "NVIDIA RTXA6000-1Q",18),
	VGPU(0x2230, 0x14fd, "NVIDIA RTXA6000-2Q",18),
	VGPU(0x2230, 0x14fe, "NVIDIA RTXA6000-3Q",18),
	VGPU(0x2230, 0x14ff, "NVIDIA RTXA6000-4Q",18),
	VGPU(0x2230, 0x1500, "NVIDIA RTXA6000-6Q",18),
	VGPU(0x2230, 0x1501, "NVIDIA RTXA6000-8Q",18),
	VGPU(0x2230, 0x1502, "NVIDIA RTXA6000-12Q",19),
	VGPU(0x2230, 0x1503, "NVIDIA RTXA6000-16Q",19),
	VGPU(0x2230, 0x1504, "NVIDIA RTXA6000-24Q",19),
	VGPU(0x2230, 0x1505, "NVIDIA RTXA6000-48Q",19),
	VGPU(0x2230, 0x1506, "NVIDIA RTXA6000-1A",18),
	VGPU(0x2230, 0x1507, "NVIDIA RTXA6000-2A",18),
	VGPU(0x2230, 0x1508, "NVIDIA RTXA6000-3A",18),
	VGPU(0x2230, 0x1509, "NVIDIA RTXA6000-4A",18),
	VGPU(0x2230, 0x150a, "NVIDIA RTXA6000-6A",18),
	VGPU(0x2230, 0x150b, "NVIDIA RTXA6000-8A",18),
	VGPU(0x2230, 0x150c, "NVIDIA RTXA6000-12A",19),
	VGPU(0x2230, 0x150d, "NVIDIA RTXA6000-16A",19),
	VGPU(0x2230, 0x150e, "NVIDIA RTXA6000-24A",19),
	VGPU(0x2230, 0x150f, "NVIDIA RTXA6000-48A",19),
	VGPU(0x2230, 0x1514, "NVIDIA RTXA6000-4C",18),
	VGPU(0x2230, 0x1515, "NVIDIA RTXA6000-6C",18),
	VGPU(0x2230, 0x1516, "NVIDIA RTXA6000-8C",18),
	VGPU(0x2230, 0x1517, "NVIDIA RTXA6000-12C",19),
	VGPU(0x2230, 0x1518, "NVIDIA RTXA6000-16C",19),
	VGPU(0x2230, 0x1519, "NVIDIA RTXA6000-24C",19),
	VGPU(0x2230, 0x151a, "NVIDIA RTXA6000-48C",19),

	{ 0 } /* Sentinel */
};

#undef VGPU

static const uint8_t vgpu_unlock_magic_start[0x10] = {
	0xf3, 0xf5, 0x9e, 0x3d, 0x13, 0x91, 0x75, 0x18,
	0x6a, 0x7b, 0x55, 0xed, 0xce, 0x5d, 0x84, 0x67
};

static const uint8_t vgpu_unlock_magic_sacrifice[0x10] = {
	0x46, 0x4f, 0x39, 0x49, 0x74, 0x91, 0xd7, 0x0f,
	0xbc, 0x65, 0xc2, 0x70, 0xdd, 0xdd, 0x11, 0x54
};

static bool vgpu_unlock_patch_applied = FALSE;

static bool vgpu_unlock_bar3_mapped = FALSE;
static uint64_t vgpu_unlock_bar3_beg;
static uint64_t vgpu_unlock_bar3_end;

static uint8_t vgpu_unlock_magic[0x10];
static bool vgpu_unlock_magic_found = FALSE;

static uint8_t vgpu_unlock_key[0x10];
static bool vgpu_unlock_key_found = FALSE;

/* These need to be added to the linker script. */
extern uint8_t vgpu_unlock_nv_kern_rodata_beg;
extern uint8_t vgpu_unlock_nv_kern_rodata_end;

static uint16_t vgpu_unlock_pci_devid_to_vgpu_capable(uint16_t pci_devid)
{
	switch (pci_devid)
	{
	/* Maxwell */
	case 0x1340 ... 0x13bd:
	case 0x174d ... 0x179c:
		return 0x13bd; /* Tesla M10 */

	/* Maxwell 2.0 */
	case 0x13c0 ... 0x1436:
	case 0x1617 ... 0x1667: /* GM204 */
	case 0x17c2 ... 0x17fd: /* GM200 */
		return 0x13f2; /* Tesla M60 */
		
	/* Pascal */
	case 0x15f0 ... 0x15f1: /* GP100GL */
	case 0x1b00 ... 0x1d56:
	case 0x1725 ... 0x172f: /* GP100 */
		return 0x1b38; /* Tesla P40 */

	/* Volta GV100 */
	case 0x1d81: /* Titan V 16GB */
	case 0x1dba: /* Quadro GV100 32GB */
		return 0x1db6; /* Tesla V100 32GB PCIE */

	/* Turing */
	case 0x1e02 ... 0x1ff9:
	case 0x2182 ... 0x21d1: /* TU116 */
		return 0x1e30; /* Quadro RTX 6000 */
	
	/* Ampere */
	case 0x2200 ... 0x2600: 
		return 0x2230; /* RTX A6000 */
	}

	return pci_devid;
}

/* Our own memcmp that will bypass buffer overflow checks. */
static int vgpu_unlock_memcmp(const void *a, const void *b, size_t size)
{
	uint8_t *pa = (uint8_t*)a;
	uint8_t *pb = (uint8_t*)b;

	while (size--)
	{
		if (*pa != *pb)
		{
			return *pa - *pb;
		}

		pa++;
		pb++;
	}

	return 0;
}

/* Search for a certain pattern in the .rodata section of nv-kern.o_binary. */
static void *vgpu_unlock_find_in_rodata(const void *val, size_t size)
{
	uint8_t *i;

	for (i = &vgpu_unlock_nv_kern_rodata_beg;
	     i < &vgpu_unlock_nv_kern_rodata_end - size;
	     i++)
	{
		if (vgpu_unlock_memcmp(val, i, size) == 0)
		{
			return i;
		}
	}

	return NULL;
}

/* Check if a value is within a range. */
static bool vgpu_unlock_in_range(uint64_t val, uint64_t beg, uint64_t end)
{
	return (val >= beg) && (val <= end);
}

/* Check if range a is completely contained within range b. */
static bool vgpu_unlock_range_contained_in(uint64_t a_beg,
                                           uint64_t a_end,
                                           uint64_t b_beg,
                                           uint64_t b_end)
{
	return vgpu_unlock_in_range(a_beg, b_beg, b_end) &&
	       vgpu_unlock_in_range(a_end, b_beg, b_end);
}

/* Check if an address points into a specific BAR of an NVIDIA GPU. */
static bool vgpu_unlock_in_bar(uint64_t addr, int bar)
{
	struct pci_dev *dev = NULL;

	while (1)
	{
		dev = pci_get_device(0x10de, PCI_ANY_ID, dev);

		if (dev)
		{
			if (vgpu_unlock_in_range(addr,
			                         pci_resource_start(dev, bar),
			                         pci_resource_end(dev, bar)))
			{
				return TRUE;
			}
		}
		else
		{
			return FALSE;
		}
	}
}

/* Check if a potential magic value is valid. */
static bool vgpu_unlock_magic_valid(const uint8_t *magic)
{
	void **gpu_list_item;

	static void **gpu_list_start = NULL;

	if (!gpu_list_start)
	{
		void *magic_start = vgpu_unlock_find_in_rodata(vgpu_unlock_magic_start,
		                                               sizeof(vgpu_unlock_magic_start));

		if (!magic_start)
		{
			LOG(KERN_ERR "Failed to find start of gpu list in .rodata\n");
			return NULL;
		}

		gpu_list_start = (void**)vgpu_unlock_find_in_rodata(&magic_start,
		                                                    sizeof(magic_start));

		if (!gpu_list_start)
		{
			LOG(KERN_ERR "Failed to find pointer to start of gpu list in .rodata\n");
			return NULL;
		}
	}

	for (gpu_list_item = gpu_list_start;
	     vgpu_unlock_in_range((uint64_t)*gpu_list_item,
	                          (uint64_t)&vgpu_unlock_nv_kern_rodata_beg,
	                          (uint64_t)&vgpu_unlock_nv_kern_rodata_end);
	     gpu_list_item += 3)
	{
		if (memcmp(magic, *gpu_list_item, 0x10) == 0)
		{
			return TRUE;
		}
	}

	return FALSE;
}

static void vgpu_unlock_apply_patch(void)
{
	uint8_t i;
	void *magic;
	void **magic_ptr;
	void **blocks_ptr;
	void **sign_ptr;
	uint8_t sign[0x20];
	uint8_t num_blocks;
	void *sac_magic;
	void **sac_magic_ptr;
	void **sac_blocks_ptr;
	void **sac_sign_ptr;
	vgpu_unlock_aes128_ctx aes_ctx;
	vgpu_unlock_vgpu_t* vgpu;
	uint8_t first_block[0x10];
	uint16_t device_id;
	
	magic = vgpu_unlock_find_in_rodata(vgpu_unlock_magic,
	                                   sizeof(vgpu_unlock_magic));
	if (!magic)
	{
		LOG(KERN_ERR "Failed to find magic in .rodata.\n");
		goto failed;
	}

	LOG(KERN_WARNING "Magic is at: %px\n", magic);

	magic_ptr = (void**)vgpu_unlock_find_in_rodata(&magic,
	                                               sizeof(magic));

	if (!magic_ptr)
	{
		LOG(KERN_ERR "Failed to find pointer to magic in .rodata.\n");
		goto failed;
	}

	blocks_ptr = magic_ptr + 1;
	sign_ptr = magic_ptr + 2;

	LOG(KERN_WARNING "Pointers found, magic: %px blocks: %px sign: %px\n",
	    magic_ptr, blocks_ptr, sign_ptr);

	if (!vgpu_unlock_in_range((uint64_t)*blocks_ptr,
	                          (uint64_t)&vgpu_unlock_nv_kern_rodata_beg,
	                          (uint64_t)&vgpu_unlock_nv_kern_rodata_end) ||
	    !vgpu_unlock_in_range((uint64_t)*sign_ptr,
	                          (uint64_t)&vgpu_unlock_nv_kern_rodata_beg,
	                          (uint64_t)&vgpu_unlock_nv_kern_rodata_end))
	{
		LOG(KERN_ERR "Invalid sign or blocks pointer.\n");
		goto failed;
	}

	num_blocks = *(uint8_t*)*blocks_ptr;

	vgpu_unlock_hmac_sha256(sign,
	                        *blocks_ptr,
	                        1 + num_blocks * 0x10,
	                        vgpu_unlock_key,
	                        sizeof(vgpu_unlock_key));

	LOG(KERN_WARNING "Generate signature is: %32ph\n", sign);

	if (memcmp(sign, *sign_ptr, sizeof(sign)) != 0)
	{
		LOG(KERN_ERR "Signatures does not match.\n");
		goto failed;
	}

	sac_magic = vgpu_unlock_find_in_rodata(vgpu_unlock_magic_sacrifice,
	                                       sizeof(vgpu_unlock_magic_sacrifice));

	if (!sac_magic)
	{
		LOG(KERN_ERR "Failed to find sacrificial magic.\n");
		goto failed;
	}

	LOG(KERN_WARNING "Sacrificial magic is at: %px\n", sac_magic);

	sac_magic_ptr = (void**) vgpu_unlock_find_in_rodata(&sac_magic,
	                                                    sizeof(sac_magic));

	if (!sac_magic_ptr)
	{
		LOG(KERN_ERR "Failed to find pointer to sacrificial magic.\n");
		goto failed;
	}

	sac_blocks_ptr = sac_magic_ptr + 1;
	sac_sign_ptr = sac_magic_ptr + 2;

	LOG(KERN_WARNING "Pointers found, sac_magic: %px sac_blocks: %px sac_sign: %px\n",
	    sac_magic_ptr, sac_blocks_ptr, sac_sign_ptr);

	if (!vgpu_unlock_in_range((uint64_t)*sac_blocks_ptr,
	                          (uint64_t)&vgpu_unlock_nv_kern_rodata_beg,
	                          (uint64_t)&vgpu_unlock_nv_kern_rodata_end) ||
	    !vgpu_unlock_in_range((uint64_t)*sac_sign_ptr,
	                          (uint64_t)&vgpu_unlock_nv_kern_rodata_beg,
	                          (uint64_t)&vgpu_unlock_nv_kern_rodata_end))
	{
		LOG(KERN_ERR "Invalid sacrificial sign or blocks pointer.\n");
		goto failed;
	}

	/* Decrypt the first block so we can access the PCI device ID. */
	memcpy(first_block, (uint8_t*)*blocks_ptr + 1, sizeof(first_block));
	vgpu_unlock_aes128_init(&aes_ctx, vgpu_unlock_key);
	vgpu_unlock_aes128_decrypt(&aes_ctx, first_block);
	LOG(KERN_WARNING "Decrypted first block is: %16ph.\n",
	    first_block);

	device_id = *((uint16_t*)first_block + 1);
	device_id = vgpu_unlock_pci_devid_to_vgpu_capable(device_id);

	/* Loop over all vGPUs and add the ones that match our device ID. */
	vgpu = vgpu_unlock_vgpu;

	while (vgpu->num_blocks != 0)
	{
		if (vgpu->dev_id != device_id)
		{
			vgpu++;
			continue;
		}

		num_blocks = vgpu->num_blocks;

		*sac_magic_ptr = vgpu_unlock_magic;
		*sac_blocks_ptr = vgpu;
		*sac_sign_ptr = &vgpu->sign;

		vgpu_unlock_aes128_init(&aes_ctx, vgpu_unlock_key);

		for (i = 0; i < num_blocks; i++)
		{
			vgpu_unlock_aes128_encrypt(&aes_ctx,
			                           (uint8_t*)vgpu + 1 + i * 0x10);
		}

		vgpu_unlock_hmac_sha256(&vgpu->sign,
		                        vgpu,
		                        1 + num_blocks * 0x10,
		                        vgpu_unlock_key,
		                        sizeof(vgpu_unlock_key));

		sac_magic_ptr += 3;
		sac_blocks_ptr = sac_magic_ptr + 1;
		sac_sign_ptr = sac_magic_ptr + 2;
		vgpu++;
	}

	vgpu_unlock_patch_applied = TRUE;

	LOG(KERN_WARNING "vGPU unlock patch applied.\n");

	return;

failed:
	vgpu_unlock_magic_found = FALSE;
	vgpu_unlock_key_found = FALSE;
}

static void *vgpu_unlock_memcpy_hook(void *dst, const void *src, size_t count)
{
	bool src_in_bar3 = vgpu_unlock_bar3_mapped &&
	                   vgpu_unlock_in_range((uint64_t)src,
	                                        vgpu_unlock_bar3_beg,
	                                        vgpu_unlock_bar3_end);

	void *result = memcpy(dst, src, count);

	if (src_in_bar3 &&
	    count == sizeof(vgpu_unlock_magic) &&
	    !vgpu_unlock_magic_found &&
	    vgpu_unlock_magic_valid(dst))
	{
		memcpy(vgpu_unlock_magic, dst, count);
		vgpu_unlock_magic_found = TRUE;

		LOG(KERN_WARNING "Magic found: %16ph\n",
		    vgpu_unlock_magic);

	}
	else if (src_in_bar3 &&
	         count == sizeof(vgpu_unlock_key) &&
	         vgpu_unlock_magic_found &&
	         !vgpu_unlock_key_found)
	{
		memcpy(vgpu_unlock_key, dst, count);
		vgpu_unlock_key_found = TRUE;

		LOG(KERN_WARNING "Key found: %16ph\n",
		    vgpu_unlock_key);
	}

	if (!vgpu_unlock_patch_applied &&
	    vgpu_unlock_magic_found &&
	    vgpu_unlock_key_found)
	{
		vgpu_unlock_apply_patch();
	}

	return result;
}

/* Check if the new IO mapping contains the magic or key. */
static void vgpu_unlock_check_map(uint64_t phys_addr,
                                  size_t size,
                                  void *virt_addr)
{
	LOG(KERN_WARNING "Remap called.\n");

	if (virt_addr &&
	    !vgpu_unlock_bar3_mapped &&
	    vgpu_unlock_in_bar(phys_addr, 3))
	{
		vgpu_unlock_bar3_beg = (uint64_t)virt_addr;
		vgpu_unlock_bar3_end = (uint64_t)virt_addr + size;
		vgpu_unlock_bar3_mapped = TRUE;
		LOG(KERN_WARNING "BAR3 mapped at: 0x%llX\n",
		    vgpu_unlock_bar3_beg);
	}
}

static void *vgpu_unlock_nv_ioremap_hook(uint64_t phys,
                                         uint64_t size)
{
	void *virt_addr = nv_ioremap(phys, size);
	vgpu_unlock_check_map(phys, size, virt_addr);
	return virt_addr;
}

static void *vgpu_unlock_nv_ioremap_nocache_hook(uint64_t phys,
                                                 uint64_t size)
{
	void *virt_addr = nv_ioremap_nocache(phys, size);
	vgpu_unlock_check_map(phys, size, virt_addr);
	return virt_addr;
}

static void *vgpu_unlock_nv_ioremap_cache_hook(uint64_t phys,
                                               uint64_t size)
{
	void *virt_addr = nv_ioremap_cache(phys, size);
	vgpu_unlock_check_map(phys, size, virt_addr);
	return virt_addr;
}

static void *vgpu_unlock_nv_ioremap_wc_hook(uint64_t phys,
                                               uint64_t size)
{
	void *virt_addr = nv_ioremap_wc(phys, size);
	vgpu_unlock_check_map(phys, size, virt_addr);
	return virt_addr;
}

#undef LOG

/* Redirect future callers to our hooks. */
#define memcpy             vgpu_unlock_memcpy_hook
#define nv_ioremap         vgpu_unlock_nv_ioremap_hook
#define nv_ioremap_nocache vgpu_unlock_nv_ioremap_nocache_hook
#define nv_ioremap_cache   vgpu_unlock_nv_ioremap_cache_hook
#define nv_ioremap_wc      vgpu_unlock_nv_ioremap_wc_hook
