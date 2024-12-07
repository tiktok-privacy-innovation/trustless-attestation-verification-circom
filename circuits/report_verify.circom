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

//! Attestation report (of an AMD SEV-SNP guest) verification program written in SNARK.
pragma circom  2.1.9;

/// Function to validate the report using the ECDSA signature algorithm.
template validate_report_ecdsa(modulus_byte, hash_len, report_max_len) {
  // The public key of the certificate consisting of the x and y coordinates.
  signal input gx[modulus_byte / 2];
  signal input gy[modulus_byte / 2];
  signal input report[report_max_len];

  // TODO: How to hash an arbitrary-length array since Circom requires all circuits
  // to be determined at compile time?
}