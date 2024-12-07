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

use std::{
    fs,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand, ValueEnum};
use json::object;
use log::LevelFilter;
use sev::firmware::guest::AttestationReport;
use sha2::{Digest, Sha384};
use x509_cert::{
    der::{Decode, DecodePem, Encode},
    Certificate,
};

const CIRCUITS_GENOA: &[&str] = &[
    "verify_genoa_cert_1",
    "verify_genoa_cert_2",
    "verify_genoa_cert_3",
    "verify_genoa_report",
];

// To be implemented
const CIRCUITS_MILAN: &[&str] = &["NULL"];

const AMD_SEV_SNP_REPORT_BODY_SIZE: usize = 0x2a0;

#[derive(Clone, Debug, ValueEnum)]
enum WitnessGenerator {
    /// Use the WASM generator to generate the witness.
    Wasm,
    /// Use the C++ generator to generate the witness.
    Cpp,
}

#[derive(Clone, Debug, ValueEnum)]
enum EncodingType {
    Pem,
    Der,
}

#[derive(Clone, Debug, ValueEnum)]
enum Arch {
    Milan,
    Genoa,
}

#[derive(Clone, Debug, Subcommand)]
enum Commands {
    /// Compile the circuits and generates the R1CS.
    Compile {
        #[clap(long, default_value = "build", help = "Path to the output file")]
        output: String,
    },
    /// Performs the trusted setup: Powers of Tau ceremony.
    Setup {
        #[clap(
            long,
            default_value = "22",
            help = "The expected upper bound of the circuit size (2^size)"
        )]
        size: usize,
        #[clap(
            long,
            default_value = "build/power_of_tau.ptau",
            help = "Path to the CRS"
        )]
        ptau_path: String,
    },
    /// Prepare the key pair.
    Keypair {
        #[clap(
            long,
            default_value = "build/power_of_tau.ptau",
            help = "Path to the CRS"
        )]
        ptau_path: String,
        #[clap(
            long,
            default_value = "build",
            help = "Path to the directory of the circuits"
        )]
        circuit_path: String,
        #[clap(long, default_value = "build", help = "Path to the output file")]
        output: String,
    },
    /// Prepare the input.
    PrepareInput {
        #[clap(
            long,
            default_value = "inputs/vcek.pem",
            help = "Path to the VCEK file"
        )]
        vcek_path: String,
        #[clap(
            long,
            default_value = "inputs/report.bin",
            help = "Path to the attestation report"
        )]
        report_path: String,
        #[clap(long, default_value = "build", help = "Path to the output directory")]
        output: String,
        #[clap(
            long,
            default_value = "pem",
            help = "The encoding type of the certificate"
        )]
        encoding: EncodingType,
    },
    /// Generates the witness for the given input.
    Witness {
        #[clap(long, default_value = "build", help = "Path to the input file")]
        input: String,
        #[clap(
            long,
            default_value = "build",
            help = "Path to the directory of the circuit"
        )]
        circuit: String,
        #[clap(
            long,
            default_value = "build",
            help = "Path to the directory of the output"
        )]
        output: String,
        #[clap(
            long,
            default_value = "wasm",
            help = "The generator to use to compute the witness"
        )]
        generator: WitnessGenerator,
    },
    /// Generates the proof for the given input.
    Prove {
        #[clap(
            long,
            default_value = "build",
            help = "Path to the proving key directory"
        )]
        key_path: String,
        #[clap(long, default_value = "build", help = "Path to the witness directory")]
        witness_path: String,
        #[clap(long, default_value = "build", help = "Path to the output directory")]
        output: String,
    },
    /// Verifies the proof for the given input.
    Verify {},
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[clap(
        long,
        default_value = "genoa",
        help = "The architecture of the SEV guest"
    )]
    arch: Arch,
    #[command(subcommand)]

    /// Sub-commands.
    command: Commands,
}

/// Convert the big-endian to little-endian.
///
/// This function also constructs the "strides" of data to the circuit.
fn convert_strides(input: &[u8], stride: usize) -> Vec<u64> {
    assert!(input.len() % stride == 0);

    let round = input.len() / stride;
    let mut res = Vec::with_capacity(round);
    for i in (0..round).rev() {
        let mut b = vec![0u8; 8];
        b[0..stride].copy_from_slice(
            &input[i * stride..(i + 1) * stride]
                .iter()
                .rev()
                .copied()
                .collect::<Vec<u8>>(),
        );
        b = b.iter().rev().copied().collect();
        res.push(u64::from_be_bytes(b.as_slice().try_into().unwrap()));
    }

    res
}

fn compile_circuit<P: AsRef<Path>>(arch: &Arch, output: P) -> Result<()> {
    let circuits = match arch {
        Arch::Milan => CIRCUITS_MILAN,
        Arch::Genoa => CIRCUITS_GENOA,
    };
    let output = output.as_ref();
    let arch = format!("{:?}", arch).to_lowercase();

    // Check if the output exists and is a directory.
    if !output.is_dir() {
        return Err(anyhow!("The output path is invalid or is not a directory"));
    }

    log::info!("Compiling the circuits for {arch} to {output:?}");

    for circuit in circuits {
        log::info!("Compiling the circuit: {circuit}");

        let out = Command::new("circom")
            .arg(format!("./circuits/{circuit}.circom"))
            .arg("--r1cs")
            .arg("--wasm")
            .arg("--sym")
            .arg("--c")
            .arg("--O2")
            .arg("--output")
            .arg(output)
            .output()?;
        if !out.status.success() {
            return Err(anyhow!(
                "Failed to compile the circuits:\n\t{}",
                String::from_utf8_lossy(&out.stderr)
            ));
        }
    }

    Ok(())
}

fn powers_of_tau<P: AsRef<Path>>(size: usize, ptau_path: P) -> Result<()> {
    log::info!("Generating the Common Reference String...");

    let ptau_path = ptau_path.as_ref();

    let out = Command::new("snarkjs")
        .arg("powersoftau")
        .arg("new")
        .arg("bn128")
        .arg(size.to_string())
        .arg("build/pot22_0000.ptau")
        .arg("-v")
        .output()?;
    if !out.status.success() {
        return Err(anyhow!(
            "Failed to start CRS generation:\n\t{}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    // Then we contribute to the ceremony.
    log::info!("Contributing to the Common Reference String...");

    let mut child = Command::new("snarkjs")
        .stdin(Stdio::piped())
        .arg("powersoftau")
        .arg("contribute")
        .arg("build/pot22_0000.ptau")
        .arg("build/pot22_0001.ptau")
        .arg("--name=\"First contribution\"")
        .arg("-v")
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(b"test_random_string\n")?;
    }

    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(anyhow!(
            "Failed to contribute to the CRS:\n\t{}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    log::info!("Preparing the Common Reference String...");
    let out = Command::new("snarkjs")
        .arg("powersoftau")
        .arg("prepare")
        .arg("phase2")
        .arg("build/pot22_0001.ptau")
        .arg(ptau_path.to_str().unwrap())
        .arg("-v")
        .output()?;
    if !out.status.success() {
        return Err(anyhow!(
            "Failed to prepare the CRS:\n\t{}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    match out.status.success() {
        false => Err(anyhow!(
            "Failed to start CRS generation:\n\t{}",
            String::from_utf8_lossy(&out.stderr)
        )),
        true => Ok(()),
    }
}

fn prepare_keypair<P: AsRef<Path>>(
    ptau_path: P,
    circuit_path: P,
    output: P,
    arch: &Arch,
) -> Result<()> {
    let circuits = match arch {
        Arch::Milan => CIRCUITS_MILAN,
        Arch::Genoa => CIRCUITS_GENOA,
    };

    let ptau_path = ptau_path.as_ref();
    let circuit_path = circuit_path.as_ref();
    let output = output.as_ref();

    for circuit in circuits {
        log::info!("Generating the proving and verification key for {circuit}...");
        let out = Command::new("snarkjs")
            .arg("groth16")
            .arg("setup")
            .arg(format!(
                "{}/{circuit}.r1cs",
                circuit_path.to_str().unwrap()
            ))
            .arg(ptau_path.to_str().unwrap())
            .arg(format!("{}/{circuit}_keys.zkey", output.to_str().unwrap()))
            .output()?;
        println!("{:?}", out.stderr);

        if !out.status.success() {
            return Err(anyhow!(
                "Failed to generate the proving and verification key:\n\t{}",
                String::from_utf8_lossy(&out.stdout)
            ));
        }

        // Export the verification key.
        log::info!("Exporting the verification key...");
        let out = Command::new("snarkjs")
            .arg("zkey")
            .arg("export")
            .arg("verificationkey")
            .arg(format!("{}/{circuit}_keys.zkey", output.to_str().unwrap()))
            .arg(format!(
                "{}/{circuit}_verification_key.json",
                output.to_str().unwrap()
            ))
            .output()?;

        if !out.status.success() {
            return Err(anyhow!(
                "Failed to export the verification key:\n\t{}",
                String::from_utf8_lossy(&out.stdout)
            ));
        }
    }

    Ok(())
}

/// Prepare the secret input.
fn prepare_input<P: AsRef<Path>>(
    vcek_path: P,
    report_path: P,
    output_path: P,
    encoding_type: &EncodingType,
) -> Result<()> {
    let vcek = fs::read(vcek_path)?;
    let report_raw = fs::read(report_path)?;
    let report = bincode::deserialize::<AttestationReport>(&report_raw)?;

    let r = report.signature.r()[..0x30]
        .iter()
        .rev()
        .copied()
        .collect::<Vec<u8>>();
    let s = report.signature.s()[..0x30]
        .iter()
        .rev()
        .copied()
        .collect::<Vec<u8>>();
    let r = convert_strides(&r, 6);
    let s = convert_strides(&s, 6);

    // Parse the certificate.
    let parsed_vcek = match encoding_type {
        EncodingType::Pem => Certificate::from_pem(vcek)?,
        EncodingType::Der => Certificate::from_der(&vcek)?,
    };
    // Note that for the VCEK certificate the public key is encoded on a specific
    // elliptic curve (secp384r1) with two coordinates, so each coordinate is 48
    // bytes long, in total 96 bytes with a prefix of 1 byte.
    let p_vcek = parsed_vcek
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .unwrap();
    let p_x = convert_strides(&p_vcek[1..49], 6);
    let p_y = convert_strides(&p_vcek[49..97], 6);

    let mut tbs_cert = vec![];
    parsed_vcek.tbs_certificate.encode_to_vec(&mut tbs_cert)?;
    let signature = parsed_vcek.signature.raw_bytes();

    // Output to the json file.
    let mut report_hasher = Sha384::new();
    report_hasher.update(&report_raw[..AMD_SEV_SNP_REPORT_BODY_SIZE]);
    let report_hash = report_hasher.finalize().to_vec();
    let report_hash = convert_strides(&report_hash, 6);

    let report_output = object! {
        "r": r,
        "s": s,
        "pubkey": vec![p_x, p_y],
        "report_hash_bytes": report_hash,
    };

    let vcek_output = object! {
        "tbs_certificate_vcek": tbs_cert,
        "signature_vcek": signature,
    };

    let empty_output = object! {
        "foo": 0,
    };

    let empty_input1 = format!(
        "{}/input_verify_genoa_cert_1.json",
        output_path.as_ref().to_str().unwrap()
    );
    let empty_input2 = format!(
        "{}/input_verify_genoa_cert_2.json",
        output_path.as_ref().to_str().unwrap()
    );
    let vcek_input = format!(
        "{}/input_verify_genoa_cert_3.json",
        output_path.as_ref().to_str().unwrap()
    );
    // Write the output to the file.
    let report_input = format!(
        "{}/input_verify_genoa_report.json",
        output_path.as_ref().to_str().unwrap()
    );
    std::fs::write(empty_input1, empty_output.to_string())?;
    std::fs::write(empty_input2, empty_output.to_string())?;
    std::fs::write(vcek_input, vcek_output.to_string())?;
    std::fs::write(report_input, report_output.to_string())?;

    Ok(())
}

/// Compute witness
fn compute_witness<P: AsRef<Path>>(
    input_path: P,
    circuit_path: P,
    generator: &WitnessGenerator,
    output: P,
    arch: &Arch,
) -> Result<()> {
    let circuits = match arch {
        Arch::Milan => CIRCUITS_MILAN,
        Arch::Genoa => CIRCUITS_GENOA,
    };

    let circuit_path = circuit_path.as_ref();
    let input_path = input_path.as_ref();
    let output = output.as_ref();
    for circuit in circuits {
        log::info!("Computing the witness for {circuit}...");

        let input = format!("{}/input_{circuit}.json", input_path.to_str().unwrap(),);
        // Before creating the proof, we need to calculate all the signals of
        // the circuit that match all the constraints of the circuit.
        let out = match generator {
            WitnessGenerator::Wasm => {
                log::info!("Using the WASM generator to compute the witness");

                Command::new("node")
                    .arg(format!(
                        "{}/{circuit}_js/generate_witness.js",
                        circuit_path.to_str().unwrap()
                    ))
                    .arg(format!(
                        "{}/{circuit}_js/{circuit}.wasm",
                        circuit_path.to_str().unwrap()
                    ))
                    .arg(input)
                    .arg(format!(
                        "{}/{circuit}_witness.wtns",
                        output.to_str().unwrap()
                    ))
                    .output()
            }
            WitnessGenerator::Cpp => {
                log::info!("To be implemented");
                let dir = format!(
                    "{}/{circuit}_circuit/{circuit}_cpp",
                    circuit_path.to_str().unwrap()
                );

                // Compile the source code first.
                let out = Command::new("make")
                    .arg("-C")
                    .arg(&dir)
                    .arg("-j")
                    .output()?;
                if !out.status.success() {
                    log::error!(
                        "Failed to compile the C++ generator:\n\t{}",
                        String::from_utf8_lossy(&out.stderr)
                    );
                    return Ok(());
                }

                log::info!("Running the C++ generator to compute the witness");

                Command::new(format!(
                    "{}/{circuit}_circuit/{circuit}_cpp/{circuit}",
                    circuit_path.to_str().unwrap()
                ))
                .arg(input)
                .arg(format!(
                    "{}/{circuit}_circuit/{circuit}_js/witness.wtns",
                    input_path.to_str().unwrap()
                ))
                .output()
            }
        }?;

        if !out.status.success() {
            return Err(anyhow!(
                "Failed to compute the witness:\n\t{}",
                String::from_utf8_lossy(&out.stderr),
            ));
        }
    }

    Ok(())
}

fn proof_generation<P: AsRef<Path>>(
    key_path: P,
    witness_path: P,
    output_path: P,
    arch: &Arch,
) -> Result<()> {
    let circuits = match arch {
        Arch::Milan => CIRCUITS_MILAN,
        Arch::Genoa => CIRCUITS_GENOA,
    };
    let key_path = key_path.as_ref();
    let witness_path = witness_path.as_ref();
    let output_path = output_path.as_ref();

    for circuit in circuits {
        log::info!("Generating the proof for {circuit}...");

        let out = Command::new("snarkjs")
            .arg("groth16")
            .arg("prove")
            .arg(format!("{}/{circuit}_keys.zkey", key_path.to_str().unwrap()))
            .arg(format!(
                "{}/{circuit}_witness.wtns",
                witness_path.to_str().unwrap()
            ))
            .arg(format!(
                "{}/{circuit}_proof.json",
                output_path.to_str().unwrap()
            ))
            .arg(format!(
                "{}/{circuit}_public.json",
                output_path.to_str().unwrap()
            ))
            .output()?;
        if !out.status.success() {
            return Err(anyhow!(
                "Failed to generate the proof:\n\t{}",
                String::from_utf8_lossy(&out.stdout)
            ));
        }
    }

    Ok(())
}

fn main() {
    env_logger::builder().filter_level(LevelFilter::Info).init();
    let args = Args::parse();

    let now = std::time::Instant::now();
    let res = match args.command {
        Commands::Compile { output } => compile_circuit(&args.arch, &output),
        Commands::Setup { size, ptau_path } => powers_of_tau(size, &ptau_path),
        Commands::Keypair {
            ptau_path,
            circuit_path,
            output,
        } => prepare_keypair(&ptau_path, &output, &circuit_path, &args.arch),
        Commands::PrepareInput {
            vcek_path,
            report_path,
            output,
            encoding,
        } => prepare_input(&vcek_path, &report_path, &output, &encoding),
        Commands::Witness {
            input,
            circuit,
            generator,
            output,
        } => compute_witness(&input, &circuit, &generator, &output, &args.arch),
        Commands::Prove {
            key_path,
            witness_path,
            output,
        } => proof_generation(&key_path, &witness_path, &output, &args.arch),
        _ => todo!(),
    };

    if let Err(e) = res {
        log::error!("{}", e);
    }

    log::info!("Elapsed time: {:?}", now.elapsed());
}
