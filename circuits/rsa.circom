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
include "../node_modules/circomlib/circuits/gates.circom"; // for bitwise operations.
include "../node_modules/passport-zk-circuits/circuits/rsa/powMod.circom";
include "helper.circom";

include "mgf1sha384.circom";

// Perform an XOR on two *bytes*.
template xor_byte() {
    signal input a;
    signal input b;
    signal output out;

    component a_bits = Num2Bits(8);
    component b_bits = Num2Bits(8);
    a_bits.in <== a;
    b_bits.in <== b;

    component xor_res[8];
    for (var i = 0; i < 8; i++) {
        xor_res[i] = XOR();
        xor_res[i].a <== a_bits.out[i];
        xor_res[i].b <== b_bits.out[i];
    }
    component bits2num = Bits2Num(8);
    for (var i = 0; i < 8; i++) {
        bits2num.in[i] <== xor_res[i].out;
    }

    out <== bits2num.out;
}

// rsassaPss + Sha384, e = 65537
//
// The signature is generated as
// 1. M' = SHA384(M)
// 2. H = SHA384(padding1 || M' || salt)
// 3. maskedDB = (padding_2 || salt) ^ MGF(H, 48) (^ is xor)
// 4. sig = maskedDB || H || 0xbc
template RsaVerifySsaPss(w, nb, e_bits, hashLen) {
    signal input sign[nb];
    signal input modulus[nb];

    // uint64_t mHASH[6] = SHA384(tbs_certificate).
    signal input message_hashed[(hashLen * w) / 8];

    // sign ** exp mod modulus
    // Decrypt the signature
    component pm = PowerMod(w, nb, e_bits);
    for (var i  = 0; i < nb; i++) {
        pm.base[i] <== sign[i];
        pm.modulus[i] <== modulus[i];
    }

    // Do a quick conversion from uint64_t[64] to uint8_t[512].
    signal pm_bytes[512];
    signal masked_db[512 - 49];
    signal hashed[48];
    // padding || H(M) || salt
    signal to_be_hashed[8 + 48 + 48];
    component db[512 - 49];
    component qwords_to_bytes_0 = qwords_to_bytes(64);
    component reverse_pm = reverse_bytes(512);
    qwords_to_bytes_0.in <== pm.out;
    reverse_pm.in <== qwords_to_bytes_0.out;
    pm_bytes <== reverse_pm.out;

    for (var i = 0; i < 512 - 49; i++) {
        masked_db[i] <== pm_bytes[i];
    }

    for (var i = 0; i < 48; i++) {
        hashed[i] <== pm_bytes[512 - 49 + i];
    }

    // 1. Check if the rightmost octet of the power of mod
    //    is 0xbc.
    pm_bytes[511] === 0xbc;

    // 2. Calculate the dbmask using MGF1 (mask generation function).
    //   dbmask = MGF(H, masked_len); this H is extracted from sig_e.
    component mfg1 = mgf1_sha384(48, 512 - 49);
    mfg1.seed <== hashed;

    // We then obtain the mask. So we can use it to do xor with the masked_db.
    //
    // This step, we obtain masked db and and the mfg result so that we recover
    // padding2 || salt. Padding length is 512 - 49 - 49 and the salt is the last
    // 48 bytes.
    for (var i = 0; i < 512 - 49; i++) {
        db[i] = xor_byte();
        db[i].a <== masked_db[i];
        db[i].b <== mfg1.out[i];
    }

    // Must be Zeroed: padding2 == 0x0.
    for (var i = 1; i < (512 - 49 - 49); i++) {
        db[i].out === 0x0;
    }

    // padding2 || 0x1 || salt
    //             ^^^^^
    db[512 - 49 - 49].out === 0x1;

    // 3. Assemble the message and hash it.
    // This is padding 1.
    for (var i = 0; i < 8; i++) {
        to_be_hashed[i] <== 0x0;
    }
    // This is H(M) = SHA384(raw_message).
    for (var i = 0; i < 48; i++) {
        to_be_hashed[8 + i] <== message_hashed[i];
    }
    // This is the salt.
    for (var i = 0; i < 48; i++) {
        to_be_hashed[8 + 48 + i] <== db[i + 512 - 49 - 48].out;
    }

    // Till now, to_be_hashed = padding1 || H(M) || salt.

    component sha384_final = Sha384_hash_bytes_digest(8 + 48 + 48);
    for (var i = 0; i < 8 + 48 + 48; i++) {
        sha384_final.inp_bytes[i] <== to_be_hashed[i];
    }

    for (var i = 0; i < 48; i++) {
        sha384_final.hash_bytes[i] === hashed[i];
    }
}
