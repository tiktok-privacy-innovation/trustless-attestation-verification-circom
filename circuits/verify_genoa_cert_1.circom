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

include "cert_verify.circom";
include "ca.circom";

template verify_ark_self_signed() {
  signal input foo;

  component self_signed = validate_x509_rsa(64, 64, 17, 6, 1046);
  component gark = ark_genoa_pubkey();
  component tbs_certificate_ark = tbs_certificate_genoa_ark();
  component signature_ark = signature_genoa_ark();

  self_signed.modulus <== gark.pubkey;
  self_signed.tbs_certificate <== tbs_certificate_ark.tbs_certificate_ark;
  self_signed.signature <== signature_ark.signature_ark;
}

/// If we do not add dummy components, the verification will fail with "scalar size does not match".
component main { public [foo] } = verify_ark_self_signed();
