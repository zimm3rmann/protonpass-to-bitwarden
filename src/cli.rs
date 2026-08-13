use std::path::PathBuf;

use clap::{ArgAction, Parser, Subcommand};

#[derive(Parser)]
#[command(name = "protonpass-to-bitwarden")]
#[command(
    version,
    about = "Convert an unencrypted Proton Pass export to native Bitwarden JSON entirely offline"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    #[command(about = "Inspect compatibility and print aggregate counts without writing output")]
    Inspect {
        #[arg(value_name = "INPUT", help = "Proton Pass ZIP export or raw data.json")]
        input: PathBuf,
    },
    #[command(about = "Write a Bitwarden JSON vault and a separate migration report")]
    Convert {
        #[arg(value_name = "INPUT", help = "Proton Pass ZIP export or raw data.json")]
        input: PathBuf,
        #[arg(
            long,
            value_name = "BITWARDEN_JSON",
            help = "New native Bitwarden JSON destination"
        )]
        output: PathBuf,
        #[arg(
            long,
            value_name = "REPORT_JSON",
            help = "New machine-readable migration report destination"
        )]
        report: PathBuf,
        #[arg(
            long,
            help = "Replace existing output and report files after safety checks"
        )]
        force: bool,
        #[arg(
            long,
            help = "Exit with code 5 after writing both files if any active record is not fully migrated"
        )]
        strict: bool,
        #[arg(
            long,
            default_value_t = true,
            action = ArgAction::Set,
            value_name = "BOOL",
            help = "Redact item names in the report; false can expose sensitive metadata"
        )]
        redact_report_names: bool,
    },
    #[command(
        name = "convert-passkeys",
        about = "Write standalone passkey-only login carriers for an already-imported Bitwarden vault",
        long_about = "Write one new minimal Bitwarden login carrier per converted passkey. This does not merge with existing Bitwarden items and intentionally omits Proton passwords, TOTP, URLs, notes, fields, and folders."
    )]
    ConvertPasskeys {
        #[arg(value_name = "INPUT", help = "Proton Pass ZIP export or raw data.json")]
        input: PathBuf,
        #[arg(
            long,
            value_name = "BITWARDEN_JSON",
            help = "New passkey-only native Bitwarden JSON destination"
        )]
        output: PathBuf,
        #[arg(
            long,
            value_name = "REPORT_JSON",
            help = "New redacted passkey migration report destination"
        )]
        report: PathBuf,
        #[arg(
            long,
            help = "Replace existing output and report files after safety checks"
        )]
        force: bool,
        #[arg(
            long,
            help = "Exit with code 5 after writing both files if any active passkey is not migrated"
        )]
        strict: bool,
        #[arg(
            long,
            default_value_t = true,
            action = ArgAction::Set,
            value_name = "BOOL",
            help = "Redact source item names in the report; false can expose sensitive metadata"
        )]
        redact_report_names: bool,
    },
}
