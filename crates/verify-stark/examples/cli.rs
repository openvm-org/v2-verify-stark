use std::{fs, path::PathBuf};

use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use clap::Parser;
use openvm_verify_stark_v2::{verify_vm_stark_proof, vk::read_vk_from_file};

#[derive(Debug, Parser)]
pub struct CliArgs {
    #[clap(long)]
    vk_path: PathBuf,

    #[clap(long)]
    proof_path: PathBuf,
}

fn main() -> eyre::Result<()> {
    let args = CliArgs::parse();

    let vk = read_vk_from_file(args.vk_path)?;
    let b64_encoded = fs::read_to_string(args.proof_path)?;
    let encoded_proof = STANDARD_NO_PAD.decode(b64_encoded.trim())?;

    verify_vm_stark_proof(&vk, &encoded_proof)?;
    println!("Proof verified successfully!");

    Ok(())
}
