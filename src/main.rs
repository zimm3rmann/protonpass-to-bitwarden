use std::path::Path;
use std::process::ExitCode;

use clap::Parser;
use protonpass_to_bitwarden::cli::{Cli, Command};
use protonpass_to_bitwarden::secure_io::{
    SecureIoError, validate_distinct_paths, write_json_atomic,
};
use protonpass_to_bitwarden::{
    AppError, InputLimits, convert_export, convert_passkeys_only, load_export,
};

const WARNING: &str =
    "WARNING: Proton Pass exports and Bitwarden imports contain plaintext vault secrets.";

fn main() -> ExitCode {
    std::panic::set_hook(Box::new(|_| {
        eprintln!("protonpass-to-bitwarden stopped after an unexpected internal failure");
    }));

    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(error.exit_kind().code())
        }
    }
}

fn run(cli: Cli) -> Result<(), AppError> {
    eprintln!("{WARNING}");
    match cli.command {
        Command::Inspect { input } => {
            let loaded = load_export(&input, InputLimits::default())?;
            let result = convert_export(&loaded.export, true);
            println!("source: {}", loaded.source.label());
            print_summary(&result.report.summary);
            Ok(())
        }
        Command::Convert {
            input,
            output,
            report,
            force,
            strict,
            redact_report_names,
        } => {
            validate_distinct_paths(&input, &output, Some(&report)).map_err(map_secure_io)?;
            preflight_destinations(&output, &report, force)?;

            if !redact_report_names {
                eprintln!("WARNING: migration report names are not redacted.");
            }

            let loaded = load_export(&input, InputLimits::default())?;
            let result = convert_export(&loaded.export, redact_report_names);
            write_json_atomic(&output, &result.export, force).map_err(map_secure_io)?;
            write_json_atomic(&report, &result.report, force).map_err(map_secure_io)?;

            print_summary(&result.report.summary);
            eprintln!("The source export was not modified or deleted.");
            if strict && result.report.summary.strict_failures > 0 {
                return Err(AppError::StrictFailure);
            }
            Ok(())
        }
        Command::ConvertPasskeys {
            input,
            output,
            report,
            force,
            strict,
            redact_report_names,
        } => {
            validate_distinct_paths(&input, &output, Some(&report)).map_err(map_secure_io)?;
            preflight_destinations(&output, &report, force)?;

            eprintln!(
                "WARNING: this creates new standalone Bitwarden login carriers; it does not merge passkeys into existing items."
            );
            if !redact_report_names {
                eprintln!("WARNING: migration report names are not redacted.");
            }

            let loaded = load_export(&input, InputLimits::default())?;
            let result = convert_passkeys_only(&loaded.export, redact_report_names);
            if result.export.items.is_empty() {
                return Err(AppError::NoConvertiblePasskeys);
            }
            write_json_atomic(&output, &result.export, force).map_err(map_secure_io)?;
            write_json_atomic(&report, &result.report, force).map_err(map_secure_io)?;

            print_summary(&result.report.summary);
            eprintln!("The source export was not modified or deleted.");
            if strict && result.report.summary.strict_failures > 0 {
                return Err(AppError::StrictFailure);
            }
            Ok(())
        }
    }
}

fn preflight_destinations(output: &Path, report: &Path, force: bool) -> Result<(), AppError> {
    if !force && (output.exists() || report.exists()) {
        return Err(AppError::DestinationExists);
    }
    Ok(())
}

fn map_secure_io(error: SecureIoError) -> AppError {
    match error {
        SecureIoError::PathConflict => AppError::ConflictingPaths,
        SecureIoError::InvalidPath
        | SecureIoError::PathInspectionFailed
        | SecureIoError::UnsafeDestination => AppError::UnsupportedPath,
        SecureIoError::DestinationExists => AppError::DestinationExists,
        SecureIoError::TemporaryFileCreationFailed => AppError::TemporaryOutput,
        SecureIoError::PermissionSetupFailed | SecureIoError::PermissionVerificationFailed => {
            AppError::OutputPermissions
        }
        SecureIoError::PersistFailed => AppError::OutputPersist,
        SecureIoError::SerializationFailed
        | SecureIoError::WriteFailed
        | SecureIoError::FlushFailed
        | SecureIoError::SyncFailed => AppError::OutputWrite,
    }
}

fn print_summary(summary: &protonpass_to_bitwarden::ReportSummary) {
    println!("items total: {}", summary.items_total);
    println!("items converted: {}", summary.items_converted);
    println!("items skipped or unsupported: {}", summary.items_skipped);
    println!("items intentionally filtered: {}", summary.items_filtered);
    println!("passkeys total: {}", summary.passkeys_total);
    println!("passkeys converted: {}", summary.passkeys_converted);
    println!("passkeys skipped: {}", summary.passkeys_skipped);
    println!("passkeys unsupported: {}", summary.passkeys_unsupported);
    println!(
        "additional passkey logins created: {}",
        summary.additional_logins_created
    );
    println!(
        "attachment-bearing item sets skipped: {}",
        summary.attachment_sets_skipped
    );
    println!("folders created: {}", summary.folders_created);
    println!("output items created: {}", summary.output_items_created);
    println!("strict failures: {}", summary.strict_failures);
}
