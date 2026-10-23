#include "desfire_crypto.h"
#include <string.h>

/* =====================================================================
 *  AES-128 Implementation (NIST FIPS-197 Standart)
 * ===================================================================== */

static const uint8_t sbox[256] = {
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
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t rsbox[256] = {
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
  0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

static const uint8_t Rcon[11] = {
  0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static void aes_key_expansion(const uint8_t *key, uint8_t *RoundKey) {
  uint8_t tempa[4];
  for (int i = 0; i < 4; ++i) {
    RoundKey[(i * 4) + 0] = key[(i * 4) + 0];
    RoundKey[(i * 4) + 1] = key[(i * 4) + 1];
    RoundKey[(i * 4) + 2] = key[(i * 4) + 2];
    RoundKey[(i * 4) + 3] = key[(i * 4) + 3];
  }
  for (int i = 4; i < 44; ++i) {
    int k = (i - 1) * 4;
    tempa[0] = RoundKey[k + 0];
    tempa[1] = RoundKey[k + 1];
    tempa[2] = RoundKey[k + 2];
    tempa[3] = RoundKey[k + 3];

    if (i % 4 == 0) {
      uint8_t u8tmp = tempa[0];
      tempa[0] = tempa[1];
      tempa[1] = tempa[2];
      tempa[2] = tempa[3];
      tempa[3] = u8tmp;

      tempa[0] = sbox[tempa[0]];
      tempa[1] = sbox[tempa[1]];
      tempa[2] = sbox[tempa[2]];
      tempa[3] = sbox[tempa[3]];

      tempa[0] ^= Rcon[i / 4];
    }
    int j = i * 4;
    k = (i - 4) * 4;
    RoundKey[j + 0] = RoundKey[k + 0] ^ tempa[0];
    RoundKey[j + 1] = RoundKey[k + 1] ^ tempa[1];
    RoundKey[j + 2] = RoundKey[k + 2] ^ tempa[2];
    RoundKey[j + 3] = RoundKey[k + 3] ^ tempa[3];
  }
}

static uint8_t xtime(uint8_t x) {
  return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

static uint8_t Multiply(uint8_t x, uint8_t y) {
  return (((y & 1) * x) ^
          ((y >> 1 & 1) * xtime(x)) ^
          ((y >> 2 & 1) * xtime(xtime(x))) ^
          ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
          ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))));
}

static void aes_encrypt_block(const uint8_t *in, uint8_t *out, const uint8_t *RoundKey) {
  uint8_t state[4][4];
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      state[j][i] = in[i * 4 + j];
    }
  }

  // Initial RoundKey addition
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      state[j][i] ^= RoundKey[i * 4 + j];
    }
  }

  // 9 Rounds
  for (int round = 1; round < 10; ++round) {
    // SubBytes
    for (int i = 0; i < 4; ++i) {
      for (int j = 0; j < 4; ++j) {
        state[i][j] = sbox[state[i][j]];
      }
    }
    // ShiftRows
    uint8_t temp;
    temp = state[1][0]; state[1][0] = state[1][1]; state[1][1] = state[1][2]; state[1][2] = state[1][3]; state[1][3] = temp;
    temp = state[2][0]; state[2][0] = state[2][2]; state[2][2] = temp;
    temp = state[2][1]; state[2][1] = state[2][3]; state[2][3] = temp;
    temp = state[3][3]; state[3][3] = state[3][2]; state[3][2] = state[3][1]; state[3][1] = state[3][0]; state[3][0] = temp;
    // MixColumns
    for (int i = 0; i < 4; ++i) {
      uint8_t a = state[0][i], b = state[1][i], c = state[2][i], d = state[3][i];
      uint8_t e = a ^ b ^ c ^ d;
      state[0][i] ^= e ^ xtime(a ^ b);
      state[1][i] ^= e ^ xtime(b ^ c);
      state[2][i] ^= e ^ xtime(c ^ d);
      state[3][i] ^= e ^ xtime(d ^ a);
    }
    // AddRoundKey
    for (int i = 0; i < 4; ++i) {
      for (int j = 0; j < 4; ++j) {
        state[j][i] ^= RoundKey[round * 16 + i * 4 + j];
      }
    }
  }

  // Final Round
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      state[i][j] = sbox[state[i][j]];
    }
  }
  uint8_t temp;
  temp = state[1][0]; state[1][0] = state[1][1]; state[1][1] = state[1][2]; state[1][2] = state[1][3]; state[1][3] = temp;
  temp = state[2][0]; state[2][0] = state[2][2]; state[2][2] = temp;
  temp = state[2][1]; state[2][1] = state[2][3]; state[2][3] = temp;
  temp = state[3][3]; state[3][3] = state[3][2]; state[3][2] = state[3][1]; state[3][1] = state[3][0]; state[3][0] = temp;

  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      state[j][i] ^= RoundKey[160 + i * 4 + j];
    }
  }

  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      out[i * 4 + j] = state[j][i];
    }
  }
}

static void aes_decrypt_block(const uint8_t *in, uint8_t *out, const uint8_t *RoundKey) {
  uint8_t state[4][4];
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      state[j][i] = in[i * 4 + j];
    }
  }

  // Initial AddRoundKey
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      state[j][i] ^= RoundKey[160 + i * 4 + j];
    }
  }

  for (int round = 9; round > 0; --round) {
    // InvShiftRows
    uint8_t temp;
    temp = state[1][3]; state[1][3] = state[1][2]; state[1][2] = state[1][1]; state[1][1] = state[1][0]; state[1][0] = temp;
    temp = state[2][0]; state[2][0] = state[2][2]; state[2][2] = temp;
    temp = state[2][1]; state[2][1] = state[2][3]; state[2][3] = temp;
    temp = state[3][0]; state[3][0] = state[3][1]; state[3][1] = state[3][2]; state[3][2] = state[3][3]; state[3][3] = temp;
    // InvSubBytes
    for (int i = 0; i < 4; ++i) {
      for (int j = 0; j < 4; ++j) {
        state[i][j] = rsbox[state[i][j]];
      }
    }
    // AddRoundKey
    for (int i = 0; i < 4; ++i) {
      for (int j = 0; j < 4; ++j) {
        state[j][i] ^= RoundKey[round * 16 + i * 4 + j];
      }
    }
    // InvMixColumns
    for (int i = 0; i < 4; ++i) {
      uint8_t a = state[0][i], b = state[1][i], c = state[2][i], d = state[3][i];
      state[0][i] = Multiply(a, 0x0e) ^ Multiply(b, 0x0b) ^ Multiply(c, 0x0d) ^ Multiply(d, 0x09);
      state[1][i] = Multiply(a, 0x09) ^ Multiply(b, 0x0e) ^ Multiply(c, 0x0b) ^ Multiply(d, 0x0d);
      state[2][i] = Multiply(a, 0x0d) ^ Multiply(b, 0x09) ^ Multiply(c, 0x0e) ^ Multiply(d, 0x0b);
      state[3][i] = Multiply(a, 0x0b) ^ Multiply(b, 0x0d) ^ Multiply(c, 0x09) ^ Multiply(d, 0x0e);
    }
  }

  // Final InvShiftRows & InvSubBytes
  uint8_t temp;
  temp = state[1][3]; state[1][3] = state[1][2]; state[1][2] = state[1][1]; state[1][1] = state[1][0]; state[1][0] = temp;
  temp = state[2][0]; state[2][0] = state[2][2]; state[2][2] = temp;
  temp = state[2][1]; state[2][1] = state[2][3]; state[2][3] = temp;
  temp = state[3][0]; state[3][0] = state[3][1]; state[3][1] = state[3][2]; state[3][2] = state[3][3]; state[3][3] = temp;

  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      state[i][j] = rsbox[state[i][j]];
    }
  }
  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      state[j][i] ^= RoundKey[i * 4 + j];
    }
  }

  for (int i = 0; i < 4; ++i) {
    for (int j = 0; j < 4; ++j) {
      out[i * 4 + j] = state[j][i];
    }
  }
}

void aes128_cbc_encrypt(const uint8_t *key16, uint8_t *iv16, const uint8_t *in, uint8_t *out, size_t len) {
  uint8_t roundKey[176];
  aes_key_expansion(key16, roundKey);

  for (size_t i = 0; i < len; i += 16) {
    uint8_t block[16];
    for (int j = 0; j < 16; ++j) {
      block[j] = in[i + j] ^ iv16[j];
    }
    aes_encrypt_block(block, out + i, roundKey);
    memcpy(iv16, out + i, 16);
  }
}

void aes128_cbc_decrypt(const uint8_t *key16, uint8_t *iv16, const uint8_t *in, uint8_t *out, size_t len) {
  uint8_t roundKey[176];
  aes_key_expansion(key16, roundKey);

  for (size_t i = 0; i < len; i += 16) {
    uint8_t nextIv[16];
    memcpy(nextIv, in + i, 16);
    aes_decrypt_block(in + i, out + i, roundKey);
    for (int j = 0; j < 16; ++j) {
      out[i + j] ^= iv16[j];
    }
    memcpy(iv16, nextIv, 16);
  }
}

/* =====================================================================
 *  DES / 2-Key Triple DES (EDE / DED) Implementation (NIST FIPS 46-3)
 * ===================================================================== */

static const uint8_t IP[64] = {
  58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
  62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
  57, 49, 41, 33, 25, 17,  9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
  61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7
};

static const uint8_t FP[64] = {
  40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
  38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
  36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
  34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41,  9, 49, 17, 57, 25
};

static const uint8_t PC1[56] = {
  57, 49, 41, 33, 25, 17,  9,  1, 58, 50, 42, 34, 26, 18,
  10,  2, 59, 51, 43, 35, 27, 19, 11,  3, 60, 52, 44, 36,
  63, 55, 47, 39, 31, 23, 15,  7, 62, 54, 46, 38, 30, 22,
  14,  6, 61, 53, 45, 37, 29, 21, 13,  5, 28, 20, 12,  4
};

static const uint8_t PC2[48] = {
  14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
  23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
  41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
  44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

static const uint8_t SHIFTS[16] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

static const uint8_t E_BIT[48] = {
  32,  1,  2,  3,  4,  5,  4,  5,  6,  7,  8,  9,
   8,  9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
  16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
  24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32,  1
};

static const uint8_t P_32[32] = {
  16,  7, 20, 21, 29, 12, 28, 17,  1, 15, 23, 26,  5, 18, 31, 10,
   2,  8, 24, 14, 32, 27,  3,  9, 19, 13, 30,  6, 22, 11,  4, 25
};

static const uint8_t SBOXES[8][64] = {
  { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 },
  { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 },
  { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 },
  { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 },
  { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 },
  { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 },
  { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 },
  { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }
};

static uint64_t get_bits(uint64_t val, const uint8_t *table, int n_in, int n_out) {
  uint64_t res = 0;
  for (int i = 0; i < n_out; ++i) {
    int bit_pos = table[i];
    uint64_t bit = (val >> (n_in - bit_pos)) & 1ULL;
    res = (res << 1) | bit;
  }
  return res;
}

static void des_key_schedule(uint64_t key, uint64_t subkeys[16]) {
  uint64_t pc1 = get_bits(key, PC1, 64, 56);
  uint32_t c = (uint32_t)(pc1 >> 28);
  uint32_t d = (uint32_t)(pc1 & 0x0FFFFFFF);

  for (int i = 0; i < 16; ++i) {
    int shift = SHIFTS[i];
    c = ((c << shift) | (c >> (28 - shift))) & 0x0FFFFFFF;
    d = ((d << shift) | (d >> (28 - shift))) & 0x0FFFFFFF;
    uint64_t cd = ((uint64_t)c << 28) | d;
    subkeys[i] = get_bits(cd, PC2, 56, 48);
  }
}

static uint64_t bytes_to_u64(const uint8_t *b) {
  uint64_t res = 0;
  for (int i = 0; i < 8; ++i) {
    res = (res << 8) | b[i];
  }
  return res;
}

static void u64_to_bytes(uint64_t v, uint8_t *b) {
  for (int i = 7; i >= 0; --i) {
    b[i] = (uint8_t)(v & 0xFF);
    v >>= 8;
  }
}

static uint64_t des_cipher_block(uint64_t block, const uint64_t subkeys[16]) {
  uint64_t ip = get_bits(block, IP, 64, 64);
  uint32_t l = (uint32_t)(ip >> 32);
  uint32_t r = (uint32_t)(ip & 0xFFFFFFFF);

  for (int i = 0; i < 16; ++i) {
    uint64_t e_r = get_bits((uint64_t)r << 32, E_BIT, 64, 48);
    uint64_t x = e_r ^ subkeys[i];

    uint32_t s_out = 0;
    for (int s = 0; s < 8; ++s) {
      uint8_t six_bits = (x >> (42 - s * 6)) & 0x3F;
      uint8_t row = ((six_bits & 0x20) >> 4) | (six_bits & 0x01);
      uint8_t col = (six_bits >> 1) & 0x0F;
      s_out = (s_out << 4) | SBOXES[s][row * 16 + col];
    }
    uint32_t f_out = (uint32_t)get_bits((uint64_t)s_out << 32, P_32, 64, 32);
    uint32_t next_r = l ^ f_out;
    l = r;
    r = next_r;
  }
  uint64_t rl = ((uint64_t)r << 32) | l;
  return get_bits(rl, FP, 64, 64);
}

// 2-Key Triple DES block encryption (EDE: Encrypt K1 -> Decrypt K2 -> Encrypt K1)
static uint64_t des3_encrypt_block(uint64_t block, const uint64_t sk1[16], const uint64_t sk2[16]) {
  uint64_t sk2_rev[16];
  for (int i = 0; i < 16; ++i) sk2_rev[i] = sk2[15 - i];

  block = des_cipher_block(block, sk1);
  block = des_cipher_block(block, sk2_rev);
  block = des_cipher_block(block, sk1);
  return block;
}

// 2-Key Triple DES block decryption (DED: Decrypt K1 -> Encrypt K2 -> Decrypt K1)
static uint64_t des3_decrypt_block(uint64_t block, const uint64_t sk1[16], const uint64_t sk2[16]) {
  uint64_t sk1_rev[16];
  for (int i = 0; i < 16; ++i) sk1_rev[i] = sk1[15 - i];

  block = des_cipher_block(block, sk1_rev);
  block = des_cipher_block(block, sk2);
  block = des_cipher_block(block, sk1_rev);
  return block;
}

void des3_2key_cbc_encrypt(const uint8_t *key16, uint8_t *iv8, const uint8_t *in, uint8_t *out, size_t len) {
  uint64_t k1 = bytes_to_u64(key16);
  uint64_t k2 = bytes_to_u64(key16 + 8);
  uint64_t sk1[16], sk2[16];
  des_key_schedule(k1, sk1);
  des_key_schedule(k2, sk2);

  uint64_t iv = bytes_to_u64(iv8);

  for (size_t i = 0; i < len; i += 8) {
    uint64_t plain = bytes_to_u64(in + i);
    uint64_t enc = des3_encrypt_block(plain ^ iv, sk1, sk2);
    u64_to_bytes(enc, out + i);
    iv = enc;
  }
  u64_to_bytes(iv, iv8);
}

void des3_2key_cbc_decrypt(const uint8_t *key16, uint8_t *iv8, const uint8_t *in, uint8_t *out, size_t len) {
  uint64_t k1 = bytes_to_u64(key16);
  uint64_t k2 = bytes_to_u64(key16 + 8);
  uint64_t sk1[16], sk2[16];
  des_key_schedule(k1, sk1);
  des_key_schedule(k2, sk2);

  uint64_t iv = bytes_to_u64(iv8);

  for (size_t i = 0; i < len; i += 8) {
    uint64_t cipher = bytes_to_u64(in + i);
    uint64_t dec = des3_decrypt_block(cipher, sk1, sk2);
    u64_to_bytes(dec ^ iv, out + i);
    iv = cipher;
  }
  u64_to_bytes(iv, iv8);
}
