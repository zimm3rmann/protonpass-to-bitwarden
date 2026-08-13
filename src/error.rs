#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExitKind {
    Usage,
    Input,
    Output,
    Strict,
}

impl ExitKind {
    pub const fn code(self) -> u8 {
        match self {
            Self::Usage => 2,
            Self::Input => 3,
            Self::Output => 4,
            Self::Strict => 5,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum AppError {
    #[error("the input file could not be opened")]
    InputOpen,
    #[error("the input exceeds the configured safety limit")]
    InputTooLarge,
    #[error("the input is not a supported Proton Pass JSON or ZIP export")]
    UnsupportedInput,
    #[error("encrypted Proton Pass exports are not supported; export an unencrypted ZIP locally")]
    EncryptedExport,
    #[error("the ZIP archive is unsafe or malformed")]
    UnsafeArchive,
    #[error("the ZIP archive does not contain exactly one Proton Pass/data.json entry")]
    MissingOrAmbiguousData,
    #[error("the Proton Pass JSON is malformed at line {line}, column {column}")]
    InvalidJson { line: usize, column: usize },
    #[error("the Proton Pass export has an unsupported top-level structure")]
    InvalidExport,
    #[error("input, output, and report paths must be distinct")]
    ConflictingPaths,
    #[error("the destination already exists; use --force only after checking the path")]
    DestinationExists,
    #[error("a private temporary output file could not be created")]
    TemporaryOutput,
    #[error("the output could not be written safely")]
    OutputWrite,
    #[error("owner-only output permissions could not be established")]
    OutputPermissions,
    #[error("the output could not be committed atomically")]
    OutputPersist,
    #[error("strict mode found records that were not fully migrated")]
    StrictFailure,
    #[error("no active passkeys could be converted; no output was written")]
    NoConvertiblePasskeys,
    #[error("a file path is invalid or unsafe")]
    UnsupportedPath,
}

impl AppError {
    pub const fn exit_kind(&self) -> ExitKind {
        match self {
            Self::DestinationExists
            | Self::TemporaryOutput
            | Self::OutputWrite
            | Self::OutputPermissions
            | Self::OutputPersist
            | Self::ConflictingPaths
            | Self::UnsupportedPath => ExitKind::Output,
            Self::StrictFailure => ExitKind::Strict,
            _ => ExitKind::Input,
        }
    }
}
