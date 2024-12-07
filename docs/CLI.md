#Command Line Interface

We provide a simple CLI tool that wraps circuit compilation, key preparation, and proof generation functionalities. You can use `cargo` to perform the following operations:

## Circuit Compilation

Compile the circuit for the corresponding AMD CPU architecture:

```sh
cargo run -r -- --arch genoa compile --output build
```

| Command Options          | Default | Description                                         |
|--------------------------|---------|-----------------------------------------------------|
| `arch`       | genoa | The architecture of the SEV guest (Currently only Genoa is supported)    |
| `output`       | build | Path to the output folder     |

This command compiles the circuit for the 'genoa' architecture and saves the output to the `output` directory.

Note: the circuit compilation consumes a lot of memory, it is recommended to run it with 64 GB RAM or more. Besides, to avoid Javascript reaching heap limit, please adjust heap limit before the compilation as follows:

```sh
export NODE_OPTIONS=--max_old_space_size=65536
```

## Powers of Tau Ceremony

**Note:** This is a simplified demonstration. In production, the shared tau should be calculated using a secure multi-party computation (MPC) involving trusted parties (e.g., Linux Foundation, Intel, Microsoft), or downloaded from a pre-computed value (e.g., the Perpetual Powers of Tau). Our implementation is for demonstration purposes only.

Generate a tau value:

```sh
cargo run -r setup --size 22 --ptau-path build/power_of_tau.ptau
```

| Command Options          | Default | Description                                         |
|--------------------------|---------|-----------------------------------------------------|
| `arch`       | genoa | The architecture of the SEV guest     |
| `size`       | 22 | The expected upper bound of the circuit size (2^size)     |
| `ptau-path`       | build/power_of_tau.ptau | Path to the output tau file     |

**Important:** Choose the circuit size carefully. A larger size will result in slower generation and increased disk usage, but this is common. For reference, generating a tau involving two parties on our server (dual Intel Xeon Platinum 8568Y+, 96 cores) took 1.5 hours and produced a 4.6 GB file for maximum circuit size $2^{22}$.

## Key Pair Generation

This step generates the coresponding proving keys and verification keys for the circuits.

```sh
cargo run -r -- --arch genoa keypair --ptau-path build/power_of_tau.ptau --output build --circuit-path build
```

This command generates key pairs in the directory specified by `--output`. The verification key can be distributed online, allowing verifiers to perform proof verification independently.

| Command Options          | Default | Description                                         |
|--------------------------|---------|-----------------------------------------------------|
| `arch`       | genoa | The architecture of the SEV guest     |
| `ptau-path` | build/power_of_tau.ptau     | Path to the tau file               |
| `circuit-path`       | build      | Path to the circuit folder                  |
| `output`       | build      | Path to the output folder                  |

## ZKP Input Generation

This step convert the certificates and the attestation resport into json format to fit the format requirements of snarkjs.
We have prepared sample inputs in the folder "inputs", and the following command generates the json files in the "build" folder by default.

```sh
cargo run -r -- --arch genoa prepare-input --vcek-path inputs/vcek.pem --report-path inputs/report.bin --output build
```

| Command Options          | Default | Description                                         |
|--------------------------|---------|-----------------------------------------------------|
| `vcek-path`       | inputs/vcek.pem | Path to the VCEK file          |
| `report-path` | inputs/report.bin     | Path to the attestation report                |
| `output`       | build      | Path to the output folder                   |


## Witness Computation

Witness computation is the process of generating the witness (private inputs) for a given circuit. This step is crucial for creating a zero-knowledge proof. To compute the witness:

```sh
cargo run -r -- --arch genoa witness --input build --circuit build --output build
```

| Command Options          | Default | Description                                         |
|--------------------------|---------|-----------------------------------------------------|
| `input`       | build | Path to the folder containing input_{circuit_name}.json files         |
| `circuit` | wasm     | Path to the circuits folder                |
| `output` | build     | Path to the output folder                |
| `generator` | wasm     | The generator to use to compute the witness (Currently only wasm is supported)               |


## Proof Generation

After computing the witness, you can generate a zero-knowledge proof:

```sh
cargo run -r -- --arch genoa prove --key-path build --witness-path build --output build
```

| Command Options          | Default | Description                                         |
|--------------------------|---------|-----------------------------------------------------|
| `key-path`       | build | Path to the proving key folder     |
| `witness-path`       | build | Path to the witness folder     |
| `output`       | build | Path to the output folder     |


The resulting `{circuit_name}_proof.json` and `{circuit_name}_public.json` files can be found in the `output` directory and can be used for verification. `{circuit_name}_proof.json` contains the SNARK proof and `{circuit_name}_public.json` contains the output of the circuit.

## Proof Verification

For each proof and the correponding circuit output, you can run the following command for verification.

```sh
snarkjs groth16 verify {path to verification_key.json} {path to circuit_output.json} {path to the proof}
```

If you apply the default values during the proof generation, the sample command for the circuit `verify_genoa_report` should be as follows:

```sh
snarkjs groth16 verify build/verify_genoa_report_verification_key.json build/verify_genoa_report_public.json build/verify_genoa_report_proof.json

```
