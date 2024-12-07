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

template verify_ark_ask_signed() {
  signal input foo;

  component ask_signed = validate_x509_rsa(64, 64, 17, 6, 1084);
  component gark = ark_genoa_pubkey();
  component tbs_certificate_ask = tbs_certificate_genoa_ask();
  component signature_ask = signature_genoa_ask();

  ask_signed.modulus <== gark.pubkey;
  ask_signed.tbs_certificate <== tbs_certificate_ask.tbs_certificate_ask;
  ask_signed.signature <== signature_ask.signature_ask;
}

component main { public [foo] } = verify_ark_ask_signed();
