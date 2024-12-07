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

//! Cerificate verification written in SNARK.

pragma circom  2.1.9;

include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/comparators.circom";
include "../lib/hash-circuits/circuits/sha2/sha384/sha384_hash_bytes.circom";

include "rsa.circom";
include "ca.circom"; // Include the hardcoded CA certificate chain.

/// Converts a uint8_t[len] array into a uint64_t[len / 8] array.
///
/// @param len The length of the input array.
///
/// @note Must be aligned with 8 bytes!
template bytes_to_qword(len) {
  assert(len % 8 == 0);

  signal input buf[len];
  signal output out[len >> 3];

  for (var i = 0; i < len; i += 8) {
    var val = 0;
    for (var j = 7; j >= 0; j--) {
      val += buf[i + j] * (1 << (8 * j));
    }

    out[i >> 3] <== val;
  }
}

/// Function to validate the X.509 certificate.
///
/// Note that this function verifies the certificate against an RSA (4096 bit) + PKCS1v15 signature.
/// The AMD root key signs the SEV key using RSA 4096, and the SEV key also uses RSA 4096 to sign the VCEK.
///
/// @param word The size of a "word" in bits.
/// @param number_blocks The number of blocks in the modulus.
/// @param e_bits The size of the exponent in bits.
/// @param hash_len The length of the hash in words.
/// @param tbs_certificate_len The length of the TBSCertificate in bytes.
///
/// @note `word` * `number_blocks` = RSA bit.
template validate_x509_rsa(word, number_blocks, e_bits, hash_len, tbs_certificate_len) {
  // uint8_t modulus[512];
  signal input modulus[512];
  // uint8_t tbs_certificate[tbs_certificate_len];
  signal input tbs_certificate[tbs_certificate_len];
  // uint8_t signature[512];
  signal input signature[512];

  // Modulus needs to be reversed.
  signal modulus_little_endian[512];
  for (var i = 0; i < 512; i++) {
    modulus_little_endian[i] <== modulus[511 - i];
  }
  // signature needs to be reversed.
  signal signature_little_endian[512];
  for (var i = 0; i < 512; i++) {
    signature_little_endian[i] <== signature[511 - i];
  }

  // Convert the modulus and signature into uint64_t arrays.
  component modulus_qwords = bytes_to_qword(512);
  component signature_qwords = bytes_to_qword(512);
  modulus_qwords.buf <== modulus;
  signature_qwords.buf <== signature_little_endian;

  // Compute the SHA384 hash of the content to be signed.
  // The whole TBSCertificate is hashed using the algorithm specified in the signature algorithm field.
  component sha384_hasher = Sha384_hash_bytes_digest(tbs_certificate_len);
  sha384_hasher.inp_bytes <== tbs_certificate;

  // Verify the signature.
  component rsa_verifier = RsaVerifySsaPss(word, number_blocks, e_bits, hash_len);
  // Value is valid.
  rsa_verifier.modulus           <== modulus_qwords.out;
  rsa_verifier.sign              <== signature_qwords.out;
  rsa_verifier.message_hashed    <== sha384_hasher.hash_bytes;
}
