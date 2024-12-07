# Overall Design of Taverns

In this documentation we will briefly describe how Taverns looks like, and how interested parties can implement this server on their own.

## Circuit Organization

In this PoC implementation for AMD SEV-SNP TEE attestation service, we incorporate the following circuits to implement the workflow in `snpguest`.

On every AMD manufacturered EPYC CPU with SNP support, there would be a unique chip secret fused into the CPU die. The AMD Key Distribution Server will use a Key Derivation Function to generate a key for every CPU (called Versioned Chip Endorsement Key (VCEK)) which is rooted back to the AMD ARK root CA. The derived VCEK will be used to sign the attestation report (or evidence in the RATS standard) to establish the authenticity of the evidence. Thus, to verify the evidence we need to do the following two things.

- Certificate chain verification. An SNP's VCEK is signed by the AMD SEV Key which is signed by the ADM Root Key. Genoa and Milan have different root keys.
- Report verification. We verify the signature of the report and the measurement of the software stack.
- (optional) Other customized policy checking. As a PoC implementation we do not intend to incorporate this.
