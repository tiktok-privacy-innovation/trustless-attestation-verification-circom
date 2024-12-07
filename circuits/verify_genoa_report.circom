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

include "../node_modules/ecdsa-p384-circom/circuits/ecdsa.circom";
include "../lib/hash-circuits/circuits/sha2/sha384/sha384_hash_bytes.circom";

template ecdsa_verify_signature() {
  signal input r[8];
  signal input s[8];
  signal input pubkey[2][8];
  signal input report_hash_bytes[8];

  component ecdsa_verify = ECDSAVerifyNoPubkeyCheck(48, 8);

  ecdsa_verify.r <== r;
  ecdsa_verify.s <== s;
  ecdsa_verify.msghash <== report_hash_bytes;
  ecdsa_verify.pubkey <== pubkey;

  ecdsa_verify.result === 1;
}

component main { public [r, s, pubkey, report_hash_bytes] } = ecdsa_verify_signature();
