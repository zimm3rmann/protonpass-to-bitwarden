use serde::Serialize;
use std::fmt;
use std::fs::{self, File, Metadata};
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use tempfile::{Builder, NamedTempFile};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SecureIoError {
    InvalidPath,
    PathInspectionFailed,
    PathConflict,
    UnsafeDestination,
    DestinationExists,
    TemporaryFileCreationFailed,
    PermissionSetupFailed,
    PermissionVerificationFailed,
    SerializationFailed,
    WriteFailed,
    FlushFailed,
    SyncFailed,
    PersistFailed,
}

impl fmt::Display for SecureIoError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPath => "a file path is invalid",
            Self::PathInspectionFailed => "a file path could not be inspected safely",
            Self::PathConflict => "input, output, and report paths must be distinct",
            Self::UnsafeDestination => "a destination is not a safe regular-file path",
            Self::DestinationExists => "a destination already exists",
            Self::TemporaryFileCreationFailed => "a private temporary file could not be created",
            Self::PermissionSetupFailed => "owner-only file permissions could not be set",
            Self::PermissionVerificationFailed => {
                "owner-only file permissions could not be verified"
            }
            Self::SerializationFailed => "JSON serialization failed",
            Self::WriteFailed => "file output failed",
            Self::FlushFailed => "file output could not be flushed",
            Self::SyncFailed => "file output could not be synchronized",
            Self::PersistFailed => "file output could not be committed atomically",
        })
    }
}

impl std::error::Error for SecureIoError {}

pub type Result<T> = std::result::Result<T, SecureIoError>;

pub fn validate_distinct_paths(input: &Path, output: &Path, report: Option<&Path>) -> Result<()> {
    let input = ComparablePath::new(input, PathRole::Input)?;
    let output = ComparablePath::new(output, PathRole::Destination)?;

    if input.conflicts_with(&output) {
        return Err(SecureIoError::PathConflict);
    }

    if let Some(report) = report {
        let report = ComparablePath::new(report, PathRole::Destination)?;
        if input.conflicts_with(&report) || output.conflicts_with(&report) {
            return Err(SecureIoError::PathConflict);
        }
    }

    Ok(())
}

pub fn write_json_atomic<T>(destination: &Path, value: &T, force: bool) -> Result<()>
where
    T: Serialize + ?Sized,
{
    write_with_private_tempfile(destination, force, |file| {
        serde_json::to_writer_pretty(&mut *file, value)
            .map_err(|_| SecureIoError::SerializationFailed)?;
        file.write_all(b"\n")
            .map_err(|_| SecureIoError::WriteFailed)
    })
}

pub fn write_bytes_atomic(destination: &Path, bytes: &[u8], force: bool) -> Result<()> {
    write_atomic_file(destination, force, |file| file.write_all(bytes))
}

pub fn write_atomic_file<F>(destination: &Path, force: bool, writer: F) -> Result<()>
where
    F: FnOnce(&mut File) -> io::Result<()>,
{
    write_with_private_tempfile(destination, force, |file| {
        writer(file).map_err(|_| SecureIoError::WriteFailed)
    })
}

fn write_with_private_tempfile<F>(destination: &Path, force: bool, writer: F) -> Result<()>
where
    F: FnOnce(&mut File) -> Result<()>,
{
    let destination = PreparedDestination::new(destination, force)?;
    let mut temporary = create_private_temporary(&destination.parent)?;
    let temporary_path = temporary.path().to_path_buf();
    let temporary_identity = required_file_identity(
        &temporary
            .as_file()
            .metadata()
            .map_err(|_| SecureIoError::PathInspectionFailed)?,
    )?;

    destination.verify_parent()?;
    destination.verify_endpoint()?;
    verify_path_identity(&temporary_path, temporary.as_file(), temporary_identity)?;
    verify_single_link(temporary.as_file())?;
    set_and_verify_owner_only(temporary.as_file())?;
    writer(temporary.as_file_mut())?;
    temporary
        .as_file_mut()
        .flush()
        .map_err(|_| SecureIoError::FlushFailed)?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|_| SecureIoError::SyncFailed)?;
    destination.verify_parent()?;
    destination.verify_endpoint()?;
    verify_path_identity(&temporary_path, temporary.as_file(), temporary_identity)?;
    verify_single_link(temporary.as_file())?;
    verify_owner_only(temporary.as_file())?;

    let persisted = persist(temporary, &destination.path, force)?;
    if let Err(error) = verify_persisted(
        &destination,
        &temporary_path,
        temporary_identity,
        &persisted,
    ) {
        remove_if_identity(&destination.path, temporary_identity);
        return Err(error);
    }
    drop(persisted);
    Ok(())
}

#[cfg(not(windows))]
fn create_private_temporary(parent: &Path) -> Result<NamedTempFile> {
    Builder::new()
        .prefix(".protonpass-to-bitwarden-")
        .tempfile_in(parent)
        .map_err(|_| SecureIoError::TemporaryFileCreationFailed)
}

#[cfg(windows)]
fn create_private_temporary(parent: &Path) -> Result<NamedTempFile> {
    use std::iter;
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{FromRawHandle, RawHandle};
    use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
    use windows_sys::Win32::Storage::FileSystem::{
        CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_TEMPORARY, FILE_SHARE_DELETE, FILE_SHARE_READ,
        FILE_SHARE_WRITE, WRITE_DAC,
    };

    let descriptor = private_windows_descriptor()?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.as_ptr(),
        bInheritHandle: 0,
    };
    Builder::new()
        .prefix(".protonpass-to-bitwarden-")
        .make_in(parent, |path| {
            let path: Vec<u16> = path
                .as_os_str()
                .encode_wide()
                .chain(iter::once(0))
                .collect();
            let handle = unsafe {
                CreateFileW(
                    path.as_ptr(),
                    GENERIC_READ | GENERIC_WRITE | WRITE_DAC,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    &attributes,
                    CREATE_NEW,
                    FILE_ATTRIBUTE_TEMPORARY,
                    std::ptr::null_mut(),
                )
            };
            if handle == INVALID_HANDLE_VALUE {
                Err(io::Error::last_os_error())
            } else {
                Ok(unsafe { File::from_raw_handle(handle as RawHandle) })
            }
        })
        .map_err(|_| SecureIoError::TemporaryFileCreationFailed)
}

fn verify_persisted(
    destination: &PreparedDestination,
    temporary_path: &Path,
    temporary_identity: FileIdentity,
    persisted: &File,
) -> Result<()> {
    destination.verify_parent()?;
    cleanup_temporary_alias(temporary_path, temporary_identity)?;
    verify_path_identity(&destination.path, persisted, temporary_identity)?;
    verify_single_link(persisted)?;
    verify_owner_only(persisted)?;
    persisted
        .sync_all()
        .map_err(|_| SecureIoError::SyncFailed)?;
    destination.sync_parent()?;
    destination.verify_parent()?;
    verify_path_identity(&destination.path, persisted, temporary_identity)
}

fn cleanup_temporary_alias(path: &Path, identity: FileIdentity) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !safe_regular_metadata(&metadata) || required_file_identity(&metadata)? != identity {
                return Err(SecureIoError::PersistFailed);
            }
            fs::remove_file(path).map_err(|_| SecureIoError::PersistFailed)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(SecureIoError::PersistFailed),
    }
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        _ => Err(SecureIoError::PersistFailed),
    }
}

fn remove_if_identity(path: &Path, identity: FileIdentity) {
    if fs::symlink_metadata(path)
        .ok()
        .filter(safe_regular_metadata)
        .and_then(|metadata| file_identity(&metadata))
        == Some(identity)
    {
        let _ = fs::remove_file(path);
    }
}

fn persist(temporary: NamedTempFile, destination: &Path, force: bool) -> Result<File> {
    if force {
        return temporary
            .persist(destination)
            .map_err(|_| SecureIoError::PersistFailed);
    }

    match temporary.persist_noclobber(destination) {
        Ok(file) => Ok(file),
        Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {
            Err(SecureIoError::DestinationExists)
        }
        Err(_) => Err(SecureIoError::PersistFailed),
    }
}

struct PreparedDestination {
    parent: PathBuf,
    path: PathBuf,
    endpoint: EndpointState,
    #[cfg(unix)]
    parent_file: File,
    #[cfg(unix)]
    parent_identity: FileIdentity,
    #[cfg(not(unix))]
    parent_identity: FileIdentity,
}

#[derive(Clone, Copy)]
enum EndpointState {
    Missing,
    Existing(FileIdentity),
}

impl PreparedDestination {
    fn new(path: &Path, force: bool) -> Result<Self> {
        let file_name = path.file_name().ok_or(SecureIoError::InvalidPath)?;
        if file_name.is_empty() {
            return Err(SecureIoError::InvalidPath);
        }

        let requested_parent = nonempty_parent(path);
        validate_requested_parent(requested_parent)?;
        let parent =
            fs::canonicalize(requested_parent).map_err(|_| SecureIoError::PathInspectionFailed)?;
        let path = parent.join(file_name);
        let endpoint = inspect_endpoint(&path, force)?;

        #[cfg(unix)]
        {
            let parent_file =
                File::open(&parent).map_err(|_| SecureIoError::PathInspectionFailed)?;
            let parent_identity = validate_parent(&parent, &parent_file)?;
            let prepared = Self {
                parent,
                path,
                endpoint,
                parent_file,
                parent_identity,
            };
            prepared.verify_parent()?;
            prepared.verify_endpoint()?;
            Ok(prepared)
        }

        #[cfg(not(unix))]
        {
            let metadata =
                fs::symlink_metadata(&parent).map_err(|_| SecureIoError::PathInspectionFailed)?;
            if !safe_directory_metadata(&metadata) {
                return Err(SecureIoError::UnsafeDestination);
            }
            let parent_identity = required_file_identity(&metadata)?;
            Ok(Self {
                parent,
                path,
                endpoint,
                parent_identity,
            })
        }
    }

    fn verify_endpoint(&self) -> Result<()> {
        match (self.endpoint, fs::symlink_metadata(&self.path)) {
            (EndpointState::Missing, Err(error)) if error.kind() == io::ErrorKind::NotFound => {
                Ok(())
            }
            (EndpointState::Existing(expected), Ok(metadata))
                if safe_regular_metadata(&metadata)
                    && required_file_identity(&metadata)? == expected =>
            {
                Ok(())
            }
            (_, Err(error)) if error.kind() != io::ErrorKind::NotFound => {
                Err(SecureIoError::PathInspectionFailed)
            }
            _ => Err(SecureIoError::UnsafeDestination),
        }
    }

    #[cfg(unix)]
    fn verify_parent(&self) -> Result<()> {
        if validate_parent(&self.parent, &self.parent_file)? == self.parent_identity {
            Ok(())
        } else {
            Err(SecureIoError::UnsafeDestination)
        }
    }

    #[cfg(not(unix))]
    fn verify_parent(&self) -> Result<()> {
        let metadata =
            fs::symlink_metadata(&self.parent).map_err(|_| SecureIoError::PathInspectionFailed)?;
        if safe_directory_metadata(&metadata)
            && required_file_identity(&metadata)? == self.parent_identity
        {
            Ok(())
        } else {
            Err(SecureIoError::UnsafeDestination)
        }
    }

    #[cfg(unix)]
    fn sync_parent(&self) -> Result<()> {
        self.parent_file
            .sync_all()
            .map_err(|_| SecureIoError::SyncFailed)
    }

    #[cfg(not(unix))]
    fn sync_parent(&self) -> Result<()> {
        Ok(())
    }
}

fn inspect_endpoint(path: &Path, force: bool) -> Result<EndpointState> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !safe_regular_metadata(&metadata) {
                return Err(SecureIoError::UnsafeDestination);
            }
            if !force {
                return Err(SecureIoError::DestinationExists);
            }
            Ok(EndpointState::Existing(required_file_identity(&metadata)?))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(EndpointState::Missing),
        Err(_) => Err(SecureIoError::PathInspectionFailed),
    }
}

#[derive(Clone, Copy)]
enum PathRole {
    Input,
    Destination,
}

struct ComparablePath {
    resolved: PathBuf,
    identity: Option<FileIdentity>,
}

impl ComparablePath {
    fn new(path: &Path, role: PathRole) -> Result<Self> {
        if path.as_os_str().is_empty() {
            return Err(SecureIoError::InvalidPath);
        }

        let endpoint = match fs::symlink_metadata(path) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == io::ErrorKind::NotFound => None,
            Err(_) => return Err(SecureIoError::PathInspectionFailed),
        };

        if matches!(role, PathRole::Destination)
            && endpoint
                .as_ref()
                .is_some_and(|metadata| !safe_regular_metadata(metadata))
        {
            return Err(SecureIoError::UnsafeDestination);
        }

        match fs::metadata(path) {
            Ok(metadata) => {
                let resolved =
                    fs::canonicalize(path).map_err(|_| SecureIoError::PathInspectionFailed)?;
                Ok(Self {
                    resolved,
                    identity: file_identity(&metadata),
                })
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound && endpoint.is_none() => {
                let file_name = path.file_name().ok_or(SecureIoError::InvalidPath)?;
                if file_name.is_empty() {
                    return Err(SecureIoError::InvalidPath);
                }
                let parent = fs::canonicalize(nonempty_parent(path))
                    .map_err(|_| SecureIoError::PathInspectionFailed)?;
                Ok(Self {
                    resolved: parent.join(file_name),
                    identity: None,
                })
            }
            Err(_) => Err(SecureIoError::PathInspectionFailed),
        }
    }

    fn conflicts_with(&self, other: &Self) -> bool {
        self.resolved == other.resolved
            || matches!(
                (&self.identity, &other.identity),
                (Some(left), Some(right)) if left == right
            )
            || platform_equivalent(&self.resolved, &other.resolved)
    }
}

fn nonempty_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(unix)]
fn validate_requested_parent(path: &Path) -> Result<()> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| SecureIoError::PathInspectionFailed)?
            .join(path)
    };
    let mut current = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                current.pop();
            }
            Component::Normal(value) => {
                current.push(value);
                let metadata = fs::symlink_metadata(&current)
                    .map_err(|_| SecureIoError::PathInspectionFailed)?;
                if metadata.file_type().is_symlink() {
                    return Err(SecureIoError::UnsafeDestination);
                }
            }
            Component::Prefix(_) => return Err(SecureIoError::InvalidPath),
        }
    }
    Ok(())
}

#[cfg(windows)]
fn validate_requested_parent(path: &Path) -> Result<()> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| SecureIoError::PathInspectionFailed)?
            .join(path)
    };
    let mut current = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => current.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                current.pop();
            }
            Component::Normal(value) => {
                current.push(value);
                let metadata = fs::symlink_metadata(&current)
                    .map_err(|_| SecureIoError::PathInspectionFailed)?;
                if metadata.file_type().is_symlink() || metadata_is_reparse_point(&metadata) {
                    return Err(SecureIoError::UnsafeDestination);
                }
            }
        }
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn validate_requested_parent(_: &Path) -> Result<()> {
    Ok(())
}

fn safe_regular_metadata(metadata: &Metadata) -> bool {
    metadata.file_type().is_file()
        && !metadata.file_type().is_symlink()
        && !metadata_is_reparse_point(metadata)
}

#[cfg(not(unix))]
fn safe_directory_metadata(metadata: &Metadata) -> bool {
    metadata.file_type().is_dir()
        && !metadata.file_type().is_symlink()
        && !metadata_is_reparse_point(metadata)
}

#[cfg(windows)]
fn metadata_is_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    metadata.file_attributes() & 0x400 != 0
}

#[cfg(not(windows))]
fn metadata_is_reparse_point(_: &Metadata) -> bool {
    false
}

#[cfg(any(windows, target_os = "macos"))]
fn platform_equivalent(left: &Path, right: &Path) -> bool {
    fn key(path: &Path) -> String {
        #[cfg(windows)]
        {
            path.to_string_lossy()
                .to_lowercase()
                .split(['/', '\\'])
                .map(|part| part.trim_end_matches([' ', '.']))
                .collect::<Vec<_>>()
                .join("\\")
        }
        #[cfg(target_os = "macos")]
        {
            use unicode_normalization::UnicodeNormalization;

            path.to_string_lossy()
                .nfd()
                .flat_map(char::to_lowercase)
                .collect()
        }
    }
    key(left) == key(right)
}

#[cfg(not(any(windows, target_os = "macos")))]
fn platform_equivalent(_: &Path, _: &Path) -> bool {
    false
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(unix)]
fn file_identity(metadata: &Metadata) -> Option<FileIdentity> {
    use std::os::unix::fs::MetadataExt;

    Some(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(windows)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    volume: u32,
    index: u64,
}

#[cfg(windows)]
fn file_identity(metadata: &Metadata) -> Option<FileIdentity> {
    use std::os::windows::fs::MetadataExt;

    Some(FileIdentity {
        volume: metadata.volume_serial_number()?,
        index: metadata.file_index()?,
    })
}

#[cfg(not(any(unix, windows)))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity;

#[cfg(not(any(unix, windows)))]
fn file_identity(_: &Metadata) -> Option<FileIdentity> {
    None
}

fn required_file_identity(metadata: &Metadata) -> Result<FileIdentity> {
    file_identity(metadata).ok_or(SecureIoError::PathInspectionFailed)
}

fn verify_path_identity(path: &Path, file: &File, expected: FileIdentity) -> Result<()> {
    let path_metadata =
        fs::symlink_metadata(path).map_err(|_| SecureIoError::PathInspectionFailed)?;
    if !safe_regular_metadata(&path_metadata)
        || required_file_identity(&path_metadata)? != expected
        || required_file_identity(
            &file
                .metadata()
                .map_err(|_| SecureIoError::PathInspectionFailed)?,
        )? != expected
    {
        return Err(SecureIoError::UnsafeDestination);
    }
    Ok(())
}

#[cfg(unix)]
fn validate_parent(path: &Path, file: &File) -> Result<FileIdentity> {
    use std::os::unix::fs::MetadataExt;

    let path_metadata =
        fs::symlink_metadata(path).map_err(|_| SecureIoError::PathInspectionFailed)?;
    let file_metadata = file
        .metadata()
        .map_err(|_| SecureIoError::PathInspectionFailed)?;
    let identity = required_file_identity(&file_metadata)?;
    if path_metadata.file_type().is_symlink()
        || !path_metadata.file_type().is_dir()
        || !file_metadata.is_dir()
        || required_file_identity(&path_metadata)? != identity
        || file_metadata.uid() != effective_user_id()
    {
        return Err(SecureIoError::UnsafeDestination);
    }
    let mode = file_metadata.mode();
    if mode & 0o022 != 0 && mode & 0o1000 == 0 {
        return Err(SecureIoError::UnsafeDestination);
    }
    Ok(identity)
}

#[cfg(unix)]
fn effective_user_id() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    unsafe { geteuid() }
}

#[cfg(unix)]
fn verify_single_link(file: &File) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    if file
        .metadata()
        .map_err(|_| SecureIoError::PathInspectionFailed)?
        .nlink()
        == 1
    {
        Ok(())
    } else {
        Err(SecureIoError::UnsafeDestination)
    }
}

#[cfg(windows)]
fn verify_single_link(file: &File) -> Result<()> {
    use std::os::windows::fs::MetadataExt;

    if file
        .metadata()
        .map_err(|_| SecureIoError::PathInspectionFailed)?
        .number_of_links()
        == Some(1)
    {
        Ok(())
    } else {
        Err(SecureIoError::UnsafeDestination)
    }
}

#[cfg(not(any(unix, windows)))]
fn verify_single_link(_: &File) -> Result<()> {
    Err(SecureIoError::PathInspectionFailed)
}

#[cfg(unix)]
fn set_and_verify_owner_only(file: &File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| SecureIoError::PermissionSetupFailed)?;
    verify_owner_only(file)
}

#[cfg(windows)]
fn set_and_verify_owner_only(file: &File) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Security::{
        DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, SetKernelObjectSecurity,
    };

    let descriptor = private_windows_descriptor()?;
    let information = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    let result = unsafe {
        SetKernelObjectSecurity(file.as_raw_handle() as _, information, descriptor.as_ptr())
    };
    if result == 0 {
        return Err(SecureIoError::PermissionSetupFailed);
    }
    verify_owner_only(file)
}

#[cfg(not(any(unix, windows)))]
fn set_and_verify_owner_only(_: &File) -> Result<()> {
    Err(SecureIoError::PermissionSetupFailed)
}

#[cfg(unix)]
fn verify_owner_only(file: &File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mode = file
        .metadata()
        .map_err(|_| SecureIoError::PermissionVerificationFailed)?
        .permissions()
        .mode()
        & 0o777;
    if mode == 0o600 {
        Ok(())
    } else {
        Err(SecureIoError::PermissionVerificationFailed)
    }
}

#[cfg(windows)]
fn verify_owner_only(file: &File) -> Result<()> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Security::{DACL_SECURITY_INFORMATION, GetKernelObjectSecurity};

    let expected =
        private_windows_descriptor().map_err(|_| SecureIoError::PermissionVerificationFailed)?;
    let information = DACL_SECURITY_INFORMATION;
    let mut needed = 0_u32;
    unsafe {
        GetKernelObjectSecurity(
            file.as_raw_handle() as _,
            information,
            std::ptr::null_mut(),
            0,
            &mut needed,
        );
    }
    if needed == 0 {
        return Err(SecureIoError::PermissionVerificationFailed);
    }
    let word_size = std::mem::size_of::<usize>();
    let mut storage = vec![0_usize; (needed as usize).div_ceil(word_size)];
    let actual = storage.as_mut_ptr().cast();
    let result = unsafe {
        GetKernelObjectSecurity(
            file.as_raw_handle() as _,
            information,
            actual,
            needed,
            &mut needed,
        )
    };
    if result == 0 || !windows_dacl_matches(expected.as_ptr(), actual)? {
        return Err(SecureIoError::PermissionVerificationFailed);
    }
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn verify_owner_only(_: &File) -> Result<()> {
    Err(SecureIoError::PermissionVerificationFailed)
}

#[cfg(windows)]
struct WindowsSecurityDescriptor(windows_sys::Win32::Security::PSECURITY_DESCRIPTOR);

#[cfg(windows)]
impl WindowsSecurityDescriptor {
    fn as_ptr(&self) -> windows_sys::Win32::Security::PSECURITY_DESCRIPTOR {
        self.0
    }
}

#[cfg(windows)]
impl Drop for WindowsSecurityDescriptor {
    fn drop(&mut self) {
        unsafe {
            let _ = windows_sys::Win32::Foundation::LocalFree(self.0.cast());
        }
    }
}

#[cfg(windows)]
fn private_windows_descriptor() -> Result<WindowsSecurityDescriptor> {
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
    };

    let descriptor_text: Vec<u16> = "D:P(A;;FA;;;OW)(A;;FA;;;SY)(A;;FA;;;BA)\0"
        .encode_utf16()
        .collect();
    let mut descriptor = std::ptr::null_mut();
    let result = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            descriptor_text.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        )
    };
    if result == 0 || descriptor.is_null() {
        Err(SecureIoError::PermissionSetupFailed)
    } else {
        Ok(WindowsSecurityDescriptor(descriptor))
    }
}

#[cfg(windows)]
fn windows_dacl_matches(
    expected: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
    actual: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
) -> Result<bool> {
    use windows_sys::Win32::Security::{
        ACL, GetSecurityDescriptorControl, GetSecurityDescriptorDacl, SE_DACL_PROTECTED,
    };

    fn dacl_bytes(
        descriptor: windows_sys::Win32::Security::PSECURITY_DESCRIPTOR,
    ) -> Result<Vec<u8>> {
        let mut present = 0;
        let mut defaulted = 0;
        let mut acl: *mut ACL = std::ptr::null_mut();
        if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) }
            == 0
            || present == 0
            || acl.is_null()
        {
            return Err(SecureIoError::PermissionVerificationFailed);
        }
        let length = unsafe { (*acl).AclSize as usize };
        Ok(unsafe { std::slice::from_raw_parts(acl.cast(), length) }.to_vec())
    }

    let mut control = 0;
    let mut revision = 0;
    if unsafe { GetSecurityDescriptorControl(actual, &mut control, &mut revision) } == 0
        || control & SE_DACL_PROTECTED == 0
    {
        return Ok(false);
    }
    Ok(dacl_bytes(expected)? == dacl_bytes(actual)?)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use serde::Serializer;
    use std::cell::Cell;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use tempfile::{TempDir, tempdir as system_tempdir};

    fn tempdir() -> io::Result<TempDir> {
        let directory = system_tempdir()?;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))?;
        Ok(directory)
    }

    #[test]
    fn writes_pretty_json_with_owner_only_permissions() {
        let directory = tempdir().unwrap();
        let destination = directory.path().join("vault.json");
        let value = serde_json::json!({"fixture": "synthetic"});

        write_json_atomic(&destination, &value, false).unwrap();

        let decoded: serde_json::Value =
            serde_json::from_slice(&fs::read(&destination).unwrap()).unwrap();
        assert_eq!(decoded, value);
        assert_eq!(
            fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn establishes_permissions_before_the_writer_runs() {
        let directory = tempdir().unwrap();
        let destination = directory.path().join("vault.json");
        let observed = Cell::new(0);

        write_atomic_file(&destination, false, |file| {
            observed.set(file.metadata()?.permissions().mode() & 0o777);
            file.write_all(b"synthetic")
        })
        .unwrap();

        assert_eq!(observed.get(), 0o600);
    }

    #[test]
    fn refuses_to_overwrite_and_preserves_existing_content() {
        let directory = tempdir().unwrap();
        let destination = directory.path().join("vault.json");
        fs::write(&destination, b"original").unwrap();

        let error = write_bytes_atomic(&destination, b"replacement", false).unwrap_err();

        assert_eq!(error, SecureIoError::DestinationExists);
        assert_eq!(fs::read(&destination).unwrap(), b"original");
    }

    #[test]
    fn force_atomically_replaces_with_owner_only_permissions() {
        let directory = tempdir().unwrap();
        let destination = directory.path().join("vault.json");
        fs::write(&destination, b"original").unwrap();
        fs::set_permissions(&destination, fs::Permissions::from_mode(0o644)).unwrap();

        write_bytes_atomic(&destination, b"replacement", true).unwrap();

        assert_eq!(fs::read(&destination).unwrap(), b"replacement");
        assert_eq!(
            fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn writer_failure_preserves_existing_destination() {
        let directory = tempdir().unwrap();
        let destination = directory.path().join("vault.json");
        fs::write(&destination, b"original").unwrap();

        let error = write_atomic_file(&destination, true, |_| {
            Err(io::Error::other("synthetic failure"))
        })
        .unwrap_err();

        assert_eq!(error, SecureIoError::WriteFailed);
        assert_eq!(fs::read(&destination).unwrap(), b"original");
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    struct RefusesSerialization;

    impl Serialize for RefusesSerialization {
        fn serialize<S>(&self, _: S) -> std::result::Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            Err(<S::Error as serde::ser::Error>::custom(
                "private scalar must not escape",
            ))
        }
    }

    #[test]
    fn serialization_errors_are_redacted_and_leave_no_output() {
        let directory = tempdir().unwrap();
        let destination = directory.path().join("vault.json");

        let error = write_json_atomic(&destination, &RefusesSerialization, false).unwrap_err();

        assert_eq!(error, SecureIoError::SerializationFailed);
        assert!(!error.to_string().contains("private scalar"));
        assert!(!destination.exists());
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 0);
    }

    #[test]
    fn rejects_existing_symlink_destination() {
        let directory = tempdir().unwrap();
        let input = directory.path().join("input.json");
        let output = directory.path().join("output.json");
        fs::write(&input, b"synthetic").unwrap();
        symlink(&input, &output).unwrap();

        assert_eq!(
            validate_distinct_paths(&input, &output, None),
            Err(SecureIoError::UnsafeDestination)
        );
        assert_eq!(
            write_bytes_atomic(&output, b"replacement", true),
            Err(SecureIoError::UnsafeDestination)
        );
        assert_eq!(fs::read(&input).unwrap(), b"synthetic");
    }

    #[test]
    fn detects_input_symlink_alias() {
        let directory = tempdir().unwrap();
        let target = directory.path().join("target.json");
        let input = directory.path().join("input.json");
        fs::write(&target, b"synthetic").unwrap();
        symlink(&target, &input).unwrap();

        assert_eq!(
            validate_distinct_paths(&input, &target, None),
            Err(SecureIoError::PathConflict)
        );
    }

    #[test]
    fn detects_hard_link_alias() {
        let directory = tempdir().unwrap();
        let input = directory.path().join("input.json");
        let output = directory.path().join("output.json");
        fs::write(&input, b"synthetic").unwrap();
        fs::hard_link(&input, &output).unwrap();

        assert_eq!(
            validate_distinct_paths(&input, &output, None),
            Err(SecureIoError::PathConflict)
        );
    }

    #[test]
    fn detects_nonexistent_lexical_aliases_and_report_conflicts() {
        let directory = tempdir().unwrap();
        let input = directory.path().join("input.json");
        let output = directory.path().join("output.json");
        let output_alias = directory.path().join(".").join("output.json");
        fs::write(&input, b"synthetic").unwrap();

        assert_eq!(
            validate_distinct_paths(&input, &output, Some(&output_alias)),
            Err(SecureIoError::PathConflict)
        );
    }

    #[test]
    fn accepts_owned_private_and_sticky_directories() {
        for mode in [0o700, 0o1777] {
            let directory = tempdir().unwrap();
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(mode)).unwrap();
            let destination = directory.path().join("vault.json");

            write_bytes_atomic(&destination, b"synthetic", false).unwrap();

            assert_eq!(fs::read(destination).unwrap(), b"synthetic");
        }
    }

    #[test]
    fn rejects_group_or_world_writable_nonsticky_parent() {
        for mode in [0o770, 0o707] {
            let directory = tempdir().unwrap();
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(mode)).unwrap();
            let destination = directory.path().join("vault.json");

            assert_eq!(
                write_bytes_atomic(&destination, b"synthetic", false),
                Err(SecureIoError::UnsafeDestination)
            );
            assert!(!destination.exists());
        }
    }

    #[test]
    fn rejects_symlinked_parent_topology() {
        let directory = tempdir().unwrap();
        let real = directory.path().join("real");
        let alias = directory.path().join("alias");
        fs::create_dir(&real).unwrap();
        symlink(&real, &alias).unwrap();
        let destination = alias.join("vault.json");

        assert_eq!(
            write_bytes_atomic(&destination, b"synthetic", false),
            Err(SecureIoError::UnsafeDestination)
        );
        assert!(!real.join("vault.json").exists());
    }

    #[test]
    fn rejects_destination_created_during_write() {
        let directory = tempdir().unwrap();
        let destination = directory.path().join("vault.json");

        let error = write_atomic_file(&destination, false, |file| {
            file.write_all(b"private")?;
            fs::write(&destination, b"decoy")
        })
        .unwrap_err();

        assert_eq!(error, SecureIoError::UnsafeDestination);
        assert_eq!(fs::read(&destination).unwrap(), b"decoy");
        assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn removes_residual_temporary_hard_link_and_verifies_link_count() {
        let directory = tempdir().unwrap();
        let temporary = directory.path().join("temporary");
        let destination = directory.path().join("destination");
        fs::write(&temporary, b"synthetic").unwrap();
        fs::hard_link(&temporary, &destination).unwrap();
        let file = File::open(&destination).unwrap();
        let identity = required_file_identity(&file.metadata().unwrap()).unwrap();

        cleanup_temporary_alias(&temporary, identity).unwrap();
        verify_single_link(&file).unwrap();

        assert!(!temporary.exists());
        assert_eq!(fs::read(destination).unwrap(), b"synthetic");
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use super::*;
    use std::cell::Cell;
    use tempfile::tempdir;

    #[test]
    fn creates_temporary_file_with_private_dacl() {
        let directory = tempdir().unwrap();
        let temporary = create_private_temporary(directory.path()).unwrap();

        verify_owner_only(temporary.as_file()).unwrap();
    }

    #[test]
    fn establishes_and_verifies_private_dacl_before_writing() {
        let directory = tempdir().unwrap();
        let destination = directory.path().join("vault.json");
        let verified = Cell::new(false);

        write_atomic_file(&destination, false, |file| {
            verify_owner_only(file).map_err(io::Error::other)?;
            verified.set(true);
            file.write_all(b"synthetic")
        })
        .unwrap();

        assert!(verified.get());
        verify_owner_only(&File::open(destination).unwrap()).unwrap();
    }

    #[test]
    fn rejects_case_and_trailing_character_destination_aliases() {
        let directory = tempdir().unwrap();
        let input = directory.path().join("input.json");
        fs::write(&input, b"synthetic").unwrap();

        for alias in ["VAULT.JSON", "vault.json. "] {
            assert_eq!(
                validate_distinct_paths(
                    &input,
                    &directory.path().join("vault.json"),
                    Some(&directory.path().join(alias)),
                ),
                Err(SecureIoError::PathConflict)
            );
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn rejects_case_and_unicode_normalization_destination_aliases() {
        let directory = tempdir().unwrap();
        let input = directory.path().join("input.json");
        fs::write(&input, b"synthetic").unwrap();
        let output = directory.path().join("R\u{e9}sum\u{e9}.json");

        for alias in ["r\u{e9}sum\u{e9}.JSON", "Re\u{301}sume\u{301}.json"] {
            assert_eq!(
                validate_distinct_paths(&input, &output, Some(&directory.path().join(alias))),
                Err(SecureIoError::PathConflict)
            );
        }
    }
}
