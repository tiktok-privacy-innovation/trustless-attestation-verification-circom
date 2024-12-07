// This file is part of Trustless Attestation Verification.
//
// Copyright (C) 2024 TikTok Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

pragma circom 2.1.9;

include "../lib/hash-circuits/circuits/sha2/sha384/sha384_hash_bytes.circom";
include "../node_modules/circomlib/circuits/bitify.circom";

/// Converts a number to bits in big-endian format.
/// 1 => [0x0, 0x0, 0x0, 0x1]
/// 2 => [0x0, 0x0, 0x0, 0x2]
template to_bytes_be(n) {
  signal input in;
  signal output out[n];

  component to_bits = Num2Bits(n * 8);
  var num[n];
  to_bits.in <== in;

  for (var i = 0; i < n; i++) {
    num[i] = 0;
    for (var j = 0; j < 8; j++) {
      num[i] = num[i] * 2 + to_bits.out[i * 8 + (7 - j)];
    }
    out[3 - i] <== num[i];
  }
}

// lengths are in bytes.
//
// @param seed_len The length of the seed in bytes (typically this is the length of the hash algorithm).
// @param mask_len The length of the mask in bytes (the length with hash removed).
// @see: https://tools.ietf.org/html/rfc3447#appendix-B.2.1
template mgf1_sha384(seed_len, mask_len) {
  assert(seed_len == 48);

  signal input seed[seed_len]; // each represents a byte.
  signal output out[mask_len]; // each represents a byte.

  // If mask_len > 2^32 * hash_len, output "mask too long" and stop.
  assert(mask_len <= 0xffffffff * seed_len);
   // ceil(mask_len / hash_len).
  var iterations = (mask_len \ seed_len) + 1;

  // Let T be the empty octet string.
  var concatenated_string[iterations * seed_len];
  component sha384[iterations];
  component bytes_be[iterations];
  for (var counter = 0; counter < iterations; counter++) {
    // For counter from 0 to \ceil (maskLen / hLen) - 1, do the
    // following:
    // a. Convert counter to an octet string C of length 4.
    //    C = I2OSP(counter, 4);
    // b. Concatenate the hash of the seed and C to the octet string.
    //    T = T || SHA384(seed || C).
    // 32 bits for the counter.
    bytes_be[counter] = to_bytes_be(4);
    bytes_be[counter].in <== counter;

    sha384[counter] = Sha384_hash_bytes_digest(seed_len + 4);
    for (var i = 0; i < seed_len; i++) {
      sha384[counter].inp_bytes[i] <== seed[i];
    }
    for (var i = 0; i < 4; i++) {
      sha384[counter].inp_bytes[seed_len + i] <== bytes_be[counter].out[i];
    }

    for (var i = 0; i < seed_len; i++) {
      concatenated_string[counter * seed_len + i] = sha384[counter].hash_bytes[i];
    }
  }

  for (var i = 0; i < mask_len; i++) {
    out[i] <== concatenated_string[i];
  }
}
