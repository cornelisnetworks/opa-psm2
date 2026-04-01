/*
  This file is provided under a dual BSD/GPLv2 license.  When using or
  redistributing this file, you may do so under either license.

  GPL LICENSE SUMMARY

  Copyright(c) 2024 Tactical Computing Labs, LLC
  Copyright(c) 2021 Cornelis Networks.

  This program is free software; you can redistribute it and/or modify
  it under the terms of version 2 of the GNU General Public License as
  published by the Free Software Foundation.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  Contact Information:
  Cornelis Networks, www.cornelisnetworks.com

  BSD LICENSE

  Copyright(c) 2024 Tactical Computing Labs, LLC
  Copyright(c) 2021 Cornelis Networks.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in
      the documentation and/or other materials provided with the
      distribution.
    * Neither the name of Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived
      from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#ifndef __PSM_HASH_H__
#define __PSM_HASH_H__

inline unsigned hash_64(uint64_t a)
{
#if defined(__riscv)
    uint64_t* p = &a;
    uint64_t P  = 0x1814141ABLL;   // CRC polynomial
    uint64_t k1 =  0xA1FA6BECLL;   // remainder of x^128 divided by CRC polynomial
    uint64_t k2 =  0x9BE9878FLL;   // remainder of x^96 divided by CRC polynomial
    uint64_t k3 =  0xB1EFC5F6LL;   // remainder of x^64 divided by CRC polynomial
    uint64_t mu = 0x1FEFF7F62LL;   // x^64 divided by CRC polynomial
    uint64_t a0, a1, a2, t1, t2;
    assert(sizeof(uint64_t) >= 2);
    a0 = 0;
    // rev8(p[0]);
    a1 = rev8(p[0]);
    // Main loop: Reduce to 2x 64 bits
    for (const uint64_t *t0 = p; t0 != p+1; t0++)
    {
      a2 = rev8(*t0);
      t1 = clmulh(a0, k1);
      t2 = clmul(a0, k1);
      a0 = a1 ^ t1;
      a1 = a2 ^ t2;
    }
    // Reduce to 64 bit, add 32 bit zero padding
    t1 = clmulh(a0, k2);
    t2 = clmul(a0, k2);
    a0 = (a1 >> 32) ^ t1;
    a1 = (a1 << 32) ^ t2;
    t2 = clmul(a0, k3);
    a1 = a1 ^ t2;
    // Barrett Reduction
    t1 = clmul(a1 >> 32, mu);
    t2 = clmul(t1 >> 32, P);
    a0 = a1 ^ t2;
    return a0;
#else
    _mm_crc32_u64(0, a);
    return a;
#endif
}

inline unsigned hash_32(uint32_t a) {
#if defined(__riscv)
    uint32_t * data = &a;
    uint32_t P  = 0x814141AB;  // CRC polynomial (implicit x^32)
    //uint32_t mu = 0xFEFF7F62;  // x^64 divided by CRC polynomial
    uint32_t mu1 = 0xFF7FBFB1; // "mu" with leading 1, shifted right by 1 bit
    uint32_t crc = 0;
    for (int i = 0; i < length; i++) {
      crc ^= rev8(data[i]);
      crc = clmulr(crc, mu1);
      crc = clmul(crc, P);
   }
   return crc;
#else
   _mm_crc32_u32(0, a);
   return a;
#endif
}
