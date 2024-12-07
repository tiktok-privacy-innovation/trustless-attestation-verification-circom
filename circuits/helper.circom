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

include "../node_modules/circomlib/circuits/bitify.circom";

/// Convert an array of uint64_t[len] into an array of uint8_t[len * 8].
template qwords_to_bytes(len) {
  signal input in[len];
  signal output out[len * 8];

  // For each uint64_t we first convert them into bits.
  component num2bits[len];
  for (var i = 0; i < len; i++) {
    num2bits[i] = Num2Bits(64);
    num2bits[i].in <== in[i];
  }

  component bitstonum[len * 8];
  for (var i = 0; i < len; i++) {
    for (var j = 0; j < 8; j++) {
      bitstonum[i * 8 + j] = Bits2Num(8);

      for (var k = 0; k < 8; k++) {
        bitstonum[i * 8 + j].in[k] <== num2bits[i].out[j * 8 + k];
      }

      out[i * 8 + j] <== bitstonum[i * 8 + j].out;
    }
  }
}

template reverse_bytes(len) {
  signal input in[len];
  signal output out[len];

  for (var i = 0; i < len; i++) {
    out[i] <== in[len - 1 - i];
  }
}