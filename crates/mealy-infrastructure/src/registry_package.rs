use crate::{InstalledExtensionPackage, inspect_extension_package};
use mealy_application::{
    ExtensionHostError, InspectedRegistryPackageManifest, InspectedRegistryRelease,
    REGISTRY_EXTENSION_PACKAGE_MEDIA_TYPE, REGISTRY_SKILL_PACKAGE_MEDIA_TYPE, RegistryError,
    RegistryPackageKind, RegistryPackageManifest, inspect_registry_package_manifest, sha256_digest,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Write as _,
    path::{Component, Path},
    sync::atomic::{AtomicU64, Ordering},
};
use tar::{EntryType, Header};
use thiserror::Error;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

const TAR_BLOCK_BYTES: usize = 512;
const TAR_TRAILER_BYTES: usize = TAR_BLOCK_BYTES * 2;
const MANIFEST_PATH: &str = "manifest.json";
const MAXIMUM_ARCHIVE_ENTRIES: usize = 512;
const MAXIMUM_ARCHIVE_PATH_BYTES: usize = 256;
const MAXIMUM_EXTENSION_EXECUTABLE_BYTES: usize = 256 * 1024 * 1024;
static EXTENSION_INSTALL_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// One exact regular file retained from a strictly inspected registry package archive.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectedRegistryPackageFile {
    relative_path: String,
    bytes: Vec<u8>,
    digest: String,
    executable: bool,
}

impl InspectedRegistryPackageFile {
    /// Returns the canonical package-relative path.
    #[must_use]
    pub fn relative_path(&self) -> &str {
        &self.relative_path
    }

    /// Returns the exact immutable file bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the SHA-256 digest of the exact file bytes.
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Reports whether the package contract marks this file as executable.
    #[must_use]
    pub const fn executable(&self) -> bool {
        self.executable
    }
}

/// Authenticated, strict, in-memory registry package evidence that has not been installed.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InspectedRegistryPackageArchive {
    release: InspectedRegistryRelease,
    manifest: InspectedRegistryPackageManifest,
    archive_digest: String,
    archive_size_bytes: u64,
    files: BTreeMap<String, InspectedRegistryPackageFile>,
}

/// Failure to publish authenticated registry extension bytes as one immutable inert revision.
#[derive(Debug, Error)]
pub enum RegistryExtensionPackageError {
    /// Filesystem publication failed.
    #[error(transparent)]
    Io(#[from] std::io::Error),
    /// Authenticated package shape or destination safety invariant failed.
    #[error("registry extension package is invalid")]
    InvalidPackage,
    /// An existing content-addressed destination does not reproduce the exact package.
    #[error("registry extension package installation conflicts with existing bytes")]
    InstallationConflict,
    /// Published bytes or declared runtime dependencies fail the established extension host check.
    #[error(transparent)]
    ExtensionHost(#[from] ExtensionHostError),
}

impl InspectedRegistryPackageArchive {
    /// Returns the publisher-signed release that authenticated this archive.
    #[must_use]
    pub const fn release(&self) -> &InspectedRegistryRelease {
        &self.release
    }

    /// Returns the exact manifest bound to the signed release.
    #[must_use]
    pub const fn manifest(&self) -> &InspectedRegistryPackageManifest {
        &self.manifest
    }

    /// Returns the SHA-256 digest of the exact archive bytes.
    #[must_use]
    pub fn archive_digest(&self) -> &str {
        &self.archive_digest
    }

    /// Returns the exact authenticated archive byte length.
    #[must_use]
    pub const fn archive_size_bytes(&self) -> u64 {
        self.archive_size_bytes
    }

    /// Returns the complete canonical archive inventory, including `manifest.json`.
    #[must_use]
    pub const fn files(&self) -> &BTreeMap<String, InspectedRegistryPackageFile> {
        &self.files
    }
}

/// Safe failure while inspecting authenticated but untrusted registry package bytes.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum RegistryPackageArchiveError {
    /// Signed release or manifest evidence is invalid or inconsistent.
    #[error("registry package release or manifest evidence is invalid")]
    InvalidEvidence,
    /// Archive framing, metadata, paths, inventory, permissions, or content is invalid.
    #[error("registry package archive is invalid")]
    InvalidArchive,
}

/// Authenticates and strictly inspects one deterministic uncompressed USTAR package in memory.
///
/// This function never extracts files, loads code, writes installation state, or grants authority.
/// It accepts only canonical UTF-8 relative paths and USTAR regular files with zero ownership and
/// timestamps. Links, devices, FIFOs, sparse entries, PAX/GNU extensions, duplicate paths,
/// undeclared files, non-zero padding, and trailing content are rejected. The exact inventory must
/// agree with the separately authenticated manifest.
///
/// # Errors
///
/// Returns [`RegistryPackageArchiveError`] for release/manifest drift or any non-canonical,
/// incomplete, substituted, or excessive archive evidence.
pub fn inspect_registry_package_archive(
    release: &InspectedRegistryRelease,
    manifest_bytes: &[u8],
    archive_bytes: &[u8],
) -> Result<InspectedRegistryPackageArchive, RegistryPackageArchiveError> {
    validate_package_media_type(release)?;
    release
        .release
        .package
        .verify_bytes(archive_bytes)
        .map_err(map_registry_error)?;
    let manifest =
        inspect_registry_package_manifest(release, manifest_bytes).map_err(map_registry_error)?;
    let parsed_files = parse_canonical_ustar(archive_bytes)?;
    let files = validate_inventory(&manifest, &parsed_files)?;

    Ok(InspectedRegistryPackageArchive {
        release: release.clone(),
        manifest,
        archive_digest: sha256_digest(archive_bytes),
        archive_size_bytes: u64::try_from(archive_bytes.len())
            .map_err(|_| RegistryPackageArchiveError::InvalidArchive)?,
        files,
    })
}

/// Publishes one strictly inspected registry extension below `installation_root/MANIFEST_DIGEST`.
///
/// Publication copies only the exact in-memory authenticated manifest and executable. The
/// destination is private, content-addressed, synchronized, and re-inspected through the existing
/// extension host boundary without executing code.
///
/// # Errors
///
/// Returns [`RegistryExtensionPackageError`] for non-extension input, redirected destinations,
/// conflicting existing bytes, filesystem failure, or executable/runtime identity failure.
pub fn publish_registry_extension_package(
    package: &InspectedRegistryPackageArchive,
    installation_root: &Path,
) -> Result<InstalledExtensionPackage, RegistryExtensionPackageError> {
    let RegistryPackageManifest::Extension(inspection) = &package.manifest().manifest else {
        return Err(RegistryExtensionPackageError::InvalidPackage);
    };
    create_private_directory(installation_root)?;
    if fs::canonicalize(installation_root)? != installation_root {
        return Err(RegistryExtensionPackageError::InvalidPackage);
    }
    let destination = installation_root.join(&package.manifest().manifest_digest);
    if destination.exists() {
        verify_published_extension(package, &destination)?;
        return inspect_extension_package((**inspection).clone(), destination).map_err(Into::into);
    }
    let temporary = installation_root.join(format!(
        ".{}.tmp-{}-{}",
        package.manifest().manifest_digest,
        std::process::id(),
        EXTENSION_INSTALL_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    if temporary.exists() {
        return Err(RegistryExtensionPackageError::InstallationConflict);
    }
    create_private_directory(&temporary)?;
    let executable = &inspection.manifest.entry_point.executable;
    let executable_file = package
        .files()
        .get(executable)
        .filter(|file| file.executable())
        .ok_or(RegistryExtensionPackageError::InvalidPackage)?;
    let publication: Result<(), RegistryExtensionPackageError> = (|| {
        write_private_file(
            &temporary.join(MANIFEST_PATH),
            &package.manifest().manifest_bytes,
            false,
        )?;
        let executable_path = temporary.join(executable);
        let executable_parent = executable_path
            .parent()
            .ok_or(RegistryExtensionPackageError::InvalidPackage)?;
        create_private_directory(executable_parent)?;
        write_private_file(&executable_path, executable_file.bytes(), true)?;
        sync_tree(&temporary)?;
        fs::rename(&temporary, &destination)?;
        File::open(installation_root)?.sync_all()?;
        Ok(())
    })();
    if publication.is_err() {
        let _ = fs::remove_dir_all(&temporary);
    }
    publication?;
    verify_published_extension(package, &destination)?;
    inspect_extension_package((**inspection).clone(), destination).map_err(Into::into)
}

fn verify_published_extension(
    package: &InspectedRegistryPackageArchive,
    destination: &Path,
) -> Result<(), RegistryExtensionPackageError> {
    if fs::canonicalize(destination)? != destination {
        return Err(RegistryExtensionPackageError::InvalidPackage);
    }
    let RegistryPackageManifest::Extension(inspection) = &package.manifest().manifest else {
        return Err(RegistryExtensionPackageError::InvalidPackage);
    };
    let expected = BTreeSet::from([
        MANIFEST_PATH.to_owned(),
        inspection.manifest.entry_point.executable.clone(),
    ]);
    let mut actual = BTreeSet::new();
    collect_published_files(destination, destination, &mut actual)?;
    if actual != expected
        || fs::read(destination.join(MANIFEST_PATH))? != package.manifest().manifest_bytes
        || fs::read(destination.join(&inspection.manifest.entry_point.executable))?
            != package
                .files()
                .get(&inspection.manifest.entry_point.executable)
                .ok_or(RegistryExtensionPackageError::InvalidPackage)?
                .bytes()
    {
        return Err(RegistryExtensionPackageError::InstallationConflict);
    }
    Ok(())
}

fn collect_published_files(
    root: &Path,
    directory: &Path,
    files: &mut BTreeSet<String>,
) -> Result<(), RegistryExtensionPackageError> {
    if files.len() > 2 {
        return Err(RegistryExtensionPackageError::InstallationConflict);
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() {
            return Err(RegistryExtensionPackageError::InstallationConflict);
        }
        if metadata.is_dir() {
            collect_published_files(root, &path, files)?;
        } else if metadata.is_file() {
            let relative = path
                .strip_prefix(root)
                .map_err(|_| RegistryExtensionPackageError::InvalidPackage)?;
            if !relative
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
            {
                return Err(RegistryExtensionPackageError::InvalidPackage);
            }
            let relative = relative
                .to_str()
                .ok_or(RegistryExtensionPackageError::InvalidPackage)?
                .to_owned();
            if !files.insert(relative) {
                return Err(RegistryExtensionPackageError::InstallationConflict);
            }
        } else {
            return Err(RegistryExtensionPackageError::InstallationConflict);
        }
    }
    Ok(())
}

fn create_private_directory(path: &Path) -> Result<(), RegistryExtensionPackageError> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(RegistryExtensionPackageError::InvalidPackage);
    }
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn write_private_file(
    path: &Path,
    bytes: &[u8],
    executable: bool,
) -> Result<(), RegistryExtensionPackageError> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(if executable { 0o700 } else { 0o600 });
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn sync_tree(directory: &Path) -> Result<(), RegistryExtensionPackageError> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            sync_tree(&entry.path())?;
        }
    }
    File::open(directory)?.sync_all()?;
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParsedArchiveFile {
    bytes: Vec<u8>,
    mode: u32,
}

fn validate_package_media_type(
    release: &InspectedRegistryRelease,
) -> Result<(), RegistryPackageArchiveError> {
    let expected = match release.release.kind {
        RegistryPackageKind::Extension => REGISTRY_EXTENSION_PACKAGE_MEDIA_TYPE,
        RegistryPackageKind::Skill => REGISTRY_SKILL_PACKAGE_MEDIA_TYPE,
    };
    if release.release.package.media_type != expected {
        return Err(RegistryPackageArchiveError::InvalidEvidence);
    }
    Ok(())
}

fn map_registry_error(_: RegistryError) -> RegistryPackageArchiveError {
    RegistryPackageArchiveError::InvalidEvidence
}

fn parse_canonical_ustar(
    archive_bytes: &[u8],
) -> Result<BTreeMap<String, ParsedArchiveFile>, RegistryPackageArchiveError> {
    if archive_bytes.len() < TAR_BLOCK_BYTES + TAR_TRAILER_BYTES
        || !archive_bytes.len().is_multiple_of(TAR_BLOCK_BYTES)
    {
        return Err(RegistryPackageArchiveError::InvalidArchive);
    }

    let mut offset = 0_usize;
    let mut files = BTreeMap::new();
    loop {
        let header_end = offset
            .checked_add(TAR_BLOCK_BYTES)
            .ok_or(RegistryPackageArchiveError::InvalidArchive)?;
        let header_block = archive_bytes
            .get(offset..header_end)
            .ok_or(RegistryPackageArchiveError::InvalidArchive)?;
        if header_block.iter().all(|byte| *byte == 0) {
            let trailer_end = offset
                .checked_add(TAR_TRAILER_BYTES)
                .ok_or(RegistryPackageArchiveError::InvalidArchive)?;
            if files.is_empty()
                || trailer_end != archive_bytes.len()
                || archive_bytes[offset..trailer_end]
                    .iter()
                    .any(|byte| *byte != 0)
            {
                return Err(RegistryPackageArchiveError::InvalidArchive);
            }
            return Ok(files);
        }
        if files.len() >= MAXIMUM_ARCHIVE_ENTRIES {
            return Err(RegistryPackageArchiveError::InvalidArchive);
        }

        let header = Header::from_byte_slice(header_block);
        validate_header(header, header_block)?;
        let path_bytes = header.path_bytes();
        let path = std::str::from_utf8(path_bytes.as_ref())
            .map_err(|_| RegistryPackageArchiveError::InvalidArchive)?;
        validate_archive_path(path)?;
        let size = usize::try_from(
            header
                .size()
                .map_err(|_| RegistryPackageArchiveError::InvalidArchive)?,
        )
        .map_err(|_| RegistryPackageArchiveError::InvalidArchive)?;
        let data_start = header_end;
        let data_end = data_start
            .checked_add(size)
            .ok_or(RegistryPackageArchiveError::InvalidArchive)?;
        let padded_size = size
            .checked_add(TAR_BLOCK_BYTES - 1)
            .ok_or(RegistryPackageArchiveError::InvalidArchive)?
            / TAR_BLOCK_BYTES
            * TAR_BLOCK_BYTES;
        let padded_end = data_start
            .checked_add(padded_size)
            .ok_or(RegistryPackageArchiveError::InvalidArchive)?;
        let bytes = archive_bytes
            .get(data_start..data_end)
            .ok_or(RegistryPackageArchiveError::InvalidArchive)?;
        let padding = archive_bytes
            .get(data_end..padded_end)
            .ok_or(RegistryPackageArchiveError::InvalidArchive)?;
        if padding.iter().any(|byte| *byte != 0) {
            return Err(RegistryPackageArchiveError::InvalidArchive);
        }
        let mode = header
            .mode()
            .map_err(|_| RegistryPackageArchiveError::InvalidArchive)?;
        if files
            .insert(
                path.to_owned(),
                ParsedArchiveFile {
                    bytes: bytes.to_vec(),
                    mode,
                },
            )
            .is_some()
        {
            return Err(RegistryPackageArchiveError::InvalidArchive);
        }
        offset = padded_end;
    }
}

fn validate_header(header: &Header, bytes: &[u8]) -> Result<(), RegistryPackageArchiveError> {
    let checksum = bytes
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                u32::from(b' ')
            } else {
                u32::from(*byte)
            }
        })
        .sum::<u32>();
    let stored_checksum = header
        .cksum()
        .map_err(|_| RegistryPackageArchiveError::InvalidArchive)?;
    if checksum != stored_checksum
        || header.entry_type() != EntryType::Regular
        || header
            .uid()
            .map_err(|_| RegistryPackageArchiveError::InvalidArchive)?
            != 0
        || header
            .gid()
            .map_err(|_| RegistryPackageArchiveError::InvalidArchive)?
            != 0
        || header
            .mtime()
            .map_err(|_| RegistryPackageArchiveError::InvalidArchive)?
            != 0
        || !matches!(
            header
                .mode()
                .map_err(|_| RegistryPackageArchiveError::InvalidArchive)?,
            0o644 | 0o755
        )
        || bytes.get(257..263) != Some(b"ustar\0")
        || bytes.get(263..265) != Some(b"00")
        || bytes[157..257].iter().any(|byte| *byte != 0)
        || bytes[265..345].iter().any(|byte| *byte != 0)
        || bytes[500..512].iter().any(|byte| *byte != 0)
        || !canonical_nul_field(&bytes[0..100], false)
        || !canonical_nul_field(&bytes[345..500], true)
        || ![
            &bytes[100..108],
            &bytes[108..116],
            &bytes[116..124],
            &bytes[124..136],
            &bytes[136..148],
            &bytes[148..156],
        ]
        .into_iter()
        .all(|field| {
            field
                .iter()
                .all(|byte| matches!(*byte, 0 | b' ' | b'0'..=b'7'))
        })
    {
        return Err(RegistryPackageArchiveError::InvalidArchive);
    }
    Ok(())
}

fn canonical_nul_field(field: &[u8], empty_allowed: bool) -> bool {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    (empty_allowed || end > 0) && field[end..].iter().all(|byte| *byte == 0)
}

fn validate_archive_path(path: &str) -> Result<(), RegistryPackageArchiveError> {
    if path.is_empty()
        || path.len() > MAXIMUM_ARCHIVE_PATH_BYTES
        || path.starts_with('/')
        || path.ends_with('/')
        || path.contains('\\')
        || path.contains("//")
        || path
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
        || path.chars().any(char::is_control)
    {
        return Err(RegistryPackageArchiveError::InvalidArchive);
    }
    Ok(())
}

fn validate_inventory(
    manifest: &InspectedRegistryPackageManifest,
    parsed: &BTreeMap<String, ParsedArchiveFile>,
) -> Result<BTreeMap<String, InspectedRegistryPackageFile>, RegistryPackageArchiveError> {
    let mut expected = BTreeMap::from([(MANIFEST_PATH.to_owned(), (0o644, None, None))]);
    match &manifest.manifest {
        RegistryPackageManifest::Extension(inspection) => {
            let executable = &inspection.manifest.entry_point.executable;
            if expected
                .insert(
                    executable.clone(),
                    (
                        0o755,
                        Some(inspection.manifest.entry_point.executable_digest.as_str()),
                        None,
                    ),
                )
                .is_some()
            {
                return Err(RegistryPackageArchiveError::InvalidArchive);
            }
        }
        RegistryPackageManifest::Skill(skill) => {
            for asset in skill.instructions.iter().chain(&skill.resources) {
                if expected
                    .insert(
                        asset.relative_path.clone(),
                        (
                            0o644,
                            Some(asset.content_digest.as_str()),
                            Some(asset.size_bytes),
                        ),
                    )
                    .is_some()
                {
                    return Err(RegistryPackageArchiveError::InvalidArchive);
                }
            }
        }
    }
    if parsed.keys().collect::<BTreeSet<_>>() != expected.keys().collect::<BTreeSet<_>>() {
        return Err(RegistryPackageArchiveError::InvalidArchive);
    }
    if parsed
        .get(MANIFEST_PATH)
        .is_none_or(|file| file.bytes != manifest.manifest_bytes)
    {
        return Err(RegistryPackageArchiveError::InvalidArchive);
    }

    let instruction_paths = match &manifest.manifest {
        RegistryPackageManifest::Skill(skill) => skill
            .instructions
            .iter()
            .map(|asset| asset.relative_path.as_str())
            .collect::<BTreeSet<_>>(),
        RegistryPackageManifest::Extension(_) => BTreeSet::new(),
    };
    let mut inspected = BTreeMap::new();
    for (path, file) in parsed {
        let (expected_mode, expected_digest, expected_size) = expected
            .get(path)
            .ok_or(RegistryPackageArchiveError::InvalidArchive)?;
        let digest = sha256_digest(&file.bytes);
        let actual_size = u64::try_from(file.bytes.len())
            .map_err(|_| RegistryPackageArchiveError::InvalidArchive)?;
        if file.mode != *expected_mode
            || expected_digest.is_some_and(|expected_digest| expected_digest != digest)
            || expected_size.is_some_and(|expected_size| expected_size != actual_size)
            || (*expected_mode == 0o755 && file.bytes.len() > MAXIMUM_EXTENSION_EXECUTABLE_BYTES)
            || (instruction_paths.contains(path.as_str()) && invalid_instruction(&file.bytes))
        {
            return Err(RegistryPackageArchiveError::InvalidArchive);
        }
        inspected.insert(
            path.clone(),
            InspectedRegistryPackageFile {
                relative_path: path.clone(),
                bytes: file.bytes.clone(),
                digest,
                executable: *expected_mode == 0o755,
            },
        );
    }
    Ok(inspected)
}

fn invalid_instruction(bytes: &[u8]) -> bool {
    std::str::from_utf8(bytes).map_or(true, |text| {
        text.chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
    })
}

#[cfg(test)]
mod tests {
    use super::{
        RegistryExtensionPackageError, RegistryPackageArchiveError,
        inspect_registry_package_archive, parse_canonical_ustar,
        publish_registry_extension_package,
    };
    use mealy_application::{
        InspectedRegistryRelease, REGISTRY_EXTENSION_MANIFEST_MEDIA_TYPE,
        REGISTRY_EXTENSION_PACKAGE_MEDIA_TYPE, REGISTRY_RELEASE_CONTRACT_VERSION,
        REGISTRY_SKILL_MANIFEST_MEDIA_TYPE, REGISTRY_SKILL_PACKAGE_MEDIA_TYPE,
        RegistryContentDescriptor, RegistryPackageKind, RegistryRelease, sha256_digest,
    };
    use mealy_domain::{
        EXTENSION_MANIFEST_SCHEMA_VERSION, EffectClass, ExtensionCapabilityKind,
        ExtensionCapabilityManifest, ExtensionCompatibility, ExtensionEntryPoint,
        ExtensionFieldSchema, ExtensionHealthCheck, ExtensionId, ExtensionKind, ExtensionManifest,
        ExtensionObjectSchema, ExtensionPermissions, ExtensionScalarType,
        ExtensionShutdownBehavior, ExtensionShutdownMode, RiskClass,
        SKILL_MANIFEST_CONTRACT_VERSION, SkillAsset, SkillManifest,
    };
    use std::{
        collections::{BTreeMap, BTreeSet},
        io::Cursor,
    };
    use tar::{Builder, EntryType, Header};

    #[derive(Clone)]
    struct ArchiveEntry<'a> {
        path: &'a str,
        bytes: &'a [u8],
        mode: u32,
        mtime: u64,
        entry_type: EntryType,
    }

    #[test]
    fn deterministic_skill_and_extension_archives_remain_inert_and_exact() {
        let instruction = b"Review the requested change.\n";
        let skill = skill_manifest(instruction);
        let skill_manifest_bytes = serde_json::to_vec(&skill).expect("skill manifest");
        let skill_archive = archive(&[
            regular("manifest.json", &skill_manifest_bytes, 0o644),
            regular("instructions/review.md", instruction, 0o644),
        ]);
        let skill_release = release(
            RegistryPackageKind::Skill,
            &skill.skill_id,
            "dev.mealy",
            &skill.version,
            &skill_manifest_bytes,
            &skill_archive,
        );
        let inspected =
            inspect_registry_package_archive(&skill_release, &skill_manifest_bytes, &skill_archive)
                .expect("strict skill archive");
        assert_eq!(inspected.files().len(), 2);
        assert!(
            !inspected
                .files()
                .get("instructions/review.md")
                .expect("instruction")
                .executable()
        );
        assert_eq!(inspected.archive_digest(), sha256_digest(&skill_archive));

        let worker = b"statically linked worker";
        let extension = extension_manifest(worker);
        let extension_manifest_bytes = serde_json::to_vec(&extension).expect("extension manifest");
        let extension_archive = archive(&[
            regular("manifest.json", &extension_manifest_bytes, 0o644),
            regular("bin/worker", worker, 0o755),
        ]);
        let extension_release = release(
            RegistryPackageKind::Extension,
            &extension.name,
            &extension.publisher,
            &extension.version,
            &extension_manifest_bytes,
            &extension_archive,
        );
        let inspected = inspect_registry_package_archive(
            &extension_release,
            &extension_manifest_bytes,
            &extension_archive,
        )
        .expect("strict extension archive");
        let installed_worker = inspected.files().get("bin/worker").expect("worker");
        assert!(installed_worker.executable());
        assert_eq!(installed_worker.bytes(), worker);
        assert_eq!(installed_worker.digest(), sha256_digest(worker));

        let temporary = tempfile::tempdir().expect("temporary extension publication");
        let installation_root = temporary.path().join("extensions");
        let installed = publish_registry_extension_package(&inspected, &installation_root)
            .expect("publish exact inert extension");
        assert_eq!(installed.inspection().manifest, extension);
        assert_eq!(
            std::fs::read(installed.executable_path()).expect("published worker"),
            worker
        );
        let repeated = publish_registry_extension_package(&inspected, &installation_root)
            .expect("idempotent exact publication");
        assert_eq!(repeated, installed);

        std::fs::write(installed.executable_path(), b"substituted worker")
            .expect("substitute published worker");
        assert!(matches!(
            publish_registry_extension_package(&inspected, &installation_root),
            Err(RegistryExtensionPackageError::InstallationConflict)
        ));
    }

    #[test]
    fn archive_inventory_rejects_extra_duplicate_link_and_metadata_authority() {
        let instruction = b"Review safely.\n";
        let skill = skill_manifest(instruction);
        let manifest = serde_json::to_vec(&skill).expect("manifest");
        let cases = [
            archive(&[
                regular("manifest.json", &manifest, 0o644),
                regular("instructions/review.md", instruction, 0o644),
                regular("undeclared.txt", b"extra", 0o644),
            ]),
            archive(&[
                regular("manifest.json", &manifest, 0o644),
                regular("instructions/review.md", instruction, 0o644),
                regular("instructions/review.md", instruction, 0o644),
            ]),
            archive(&[
                regular("manifest.json", &manifest, 0o644),
                ArchiveEntry {
                    path: "instructions/review.md",
                    bytes: &[],
                    mode: 0o644,
                    mtime: 0,
                    entry_type: EntryType::Symlink,
                },
            ]),
            archive(&[
                regular("manifest.json", &manifest, 0o644),
                regular("instructions/review.md", instruction, 0o755),
            ]),
            archive(&[
                regular("manifest.json", &manifest, 0o644),
                ArchiveEntry {
                    path: "instructions/review.md",
                    bytes: instruction,
                    mode: 0o644,
                    mtime: 1,
                    entry_type: EntryType::Regular,
                },
            ]),
        ];
        for candidate in cases {
            let release = release(
                RegistryPackageKind::Skill,
                &skill.skill_id,
                "dev.mealy",
                &skill.version,
                &manifest,
                &candidate,
            );
            assert_eq!(
                inspect_registry_package_archive(&release, &manifest, &candidate),
                Err(RegistryPackageArchiveError::InvalidArchive)
            );
        }
    }

    #[test]
    fn archive_parser_rejects_traversal_bad_checksum_padding_and_trailing_content() {
        let valid = archive(&[regular("manifest.json", b"x", 0o644)]);

        let mut traversal = valid.clone();
        traversal[0..4].copy_from_slice(b"../x");
        replace_header_checksum(&mut traversal[0..512]);
        assert_eq!(
            parse_canonical_ustar(&traversal),
            Err(RegistryPackageArchiveError::InvalidArchive)
        );

        let mut bad_checksum = valid.clone();
        bad_checksum[0] ^= 1;
        assert_eq!(
            parse_canonical_ustar(&bad_checksum),
            Err(RegistryPackageArchiveError::InvalidArchive)
        );

        let mut bad_padding = valid.clone();
        bad_padding[513] = 1;
        assert_eq!(
            parse_canonical_ustar(&bad_padding),
            Err(RegistryPackageArchiveError::InvalidArchive)
        );

        let mut trailing = valid;
        trailing.extend(std::iter::repeat_n(0_u8, 512));
        assert_eq!(
            parse_canonical_ustar(&trailing),
            Err(RegistryPackageArchiveError::InvalidArchive)
        );
    }

    #[test]
    fn archive_rejects_manifest_substitution_and_instruction_control_bytes() {
        let instruction = b"Review safely.\n";
        let skill = skill_manifest(instruction);
        let manifest = serde_json::to_vec(&skill).expect("manifest");
        let substituted = archive(&[
            regular("manifest.json", b"{}", 0o644),
            regular("instructions/review.md", instruction, 0o644),
        ]);
        let substituted_release = release(
            RegistryPackageKind::Skill,
            &skill.skill_id,
            "dev.mealy",
            &skill.version,
            &manifest,
            &substituted,
        );
        assert_eq!(
            inspect_registry_package_archive(&substituted_release, &manifest, &substituted),
            Err(RegistryPackageArchiveError::InvalidArchive)
        );

        let control_instruction = b"Review\x00safely";
        let control_skill = skill_manifest(control_instruction);
        let control_manifest = serde_json::to_vec(&control_skill).expect("manifest");
        let control_archive = archive(&[
            regular("manifest.json", &control_manifest, 0o644),
            regular("instructions/review.md", control_instruction, 0o644),
        ]);
        let control_release = release(
            RegistryPackageKind::Skill,
            &control_skill.skill_id,
            "dev.mealy",
            &control_skill.version,
            &control_manifest,
            &control_archive,
        );
        assert_eq!(
            inspect_registry_package_archive(&control_release, &control_manifest, &control_archive),
            Err(RegistryPackageArchiveError::InvalidArchive)
        );
    }

    fn regular<'a>(path: &'a str, bytes: &'a [u8], mode: u32) -> ArchiveEntry<'a> {
        ArchiveEntry {
            path,
            bytes,
            mode,
            mtime: 0,
            entry_type: EntryType::Regular,
        }
    }

    fn archive(entries: &[ArchiveEntry<'_>]) -> Vec<u8> {
        let mut builder = Builder::new(Vec::new());
        for entry in entries {
            let mut header = Header::new_ustar();
            header.set_path(entry.path).expect("fixture path");
            header.set_size(u64::try_from(entry.bytes.len()).expect("fixture size"));
            header.set_mode(entry.mode);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(entry.mtime);
            header.set_entry_type(entry.entry_type);
            header.set_cksum();
            builder
                .append(&header, Cursor::new(entry.bytes))
                .expect("fixture entry");
        }
        builder.into_inner().expect("fixture archive")
    }

    fn replace_header_checksum(header: &mut [u8]) {
        header[148..156].fill(b' ');
        let checksum = header.iter().map(|byte| u64::from(*byte)).sum::<u64>();
        let encoded = format!("{checksum:06o}\0 ");
        header[148..156].copy_from_slice(encoded.as_bytes());
    }

    fn descriptor(media_type: &str, bytes: &[u8]) -> RegistryContentDescriptor {
        RegistryContentDescriptor {
            media_type: media_type.to_owned(),
            sha256_digest: sha256_digest(bytes),
            size_bytes: u64::try_from(bytes.len()).expect("fixture size"),
        }
    }

    fn release(
        kind: RegistryPackageKind,
        package_id: &str,
        publisher_id: &str,
        version: &str,
        manifest: &[u8],
        package: &[u8],
    ) -> InspectedRegistryRelease {
        let (manifest_media_type, package_media_type) = match kind {
            RegistryPackageKind::Extension => (
                REGISTRY_EXTENSION_MANIFEST_MEDIA_TYPE,
                REGISTRY_EXTENSION_PACKAGE_MEDIA_TYPE,
            ),
            RegistryPackageKind::Skill => (
                REGISTRY_SKILL_MANIFEST_MEDIA_TYPE,
                REGISTRY_SKILL_PACKAGE_MEDIA_TYPE,
            ),
        };
        InspectedRegistryRelease {
            release: RegistryRelease {
                contract_version: REGISTRY_RELEASE_CONTRACT_VERSION.to_owned(),
                registry_id: "dev.mealy.registry".to_owned(),
                package_id: package_id.to_owned(),
                kind,
                publisher_id: publisher_id.to_owned(),
                version: version.to_owned(),
                manifest: descriptor(manifest_media_type, manifest),
                package: descriptor(package_media_type, package),
                minimum_host_api: 1,
                maximum_host_api: 1,
                dependencies: Vec::new(),
                published_at_ms: 1,
            },
            payload_digest: "a".repeat(64),
            envelope_digest: "b".repeat(64),
            envelope_bytes: b"fixture envelope".to_vec(),
        }
    }

    fn skill_manifest(instruction: &[u8]) -> SkillManifest {
        SkillManifest {
            contract_version: SKILL_MANIFEST_CONTRACT_VERSION.to_owned(),
            skill_id: "dev.mealy.review".to_owned(),
            version: "1.0.0".to_owned(),
            instructions: vec![SkillAsset {
                relative_path: "instructions/review.md".to_owned(),
                media_type: "text/markdown".to_owned(),
                content_digest: sha256_digest(instruction),
                size_bytes: u64::try_from(instruction.len()).expect("fixture size"),
            }],
            resources: Vec::new(),
            required_tools: BTreeSet::new(),
        }
    }

    fn extension_manifest(worker: &[u8]) -> ExtensionManifest {
        ExtensionManifest {
            schema_version: EXTENSION_MANIFEST_SCHEMA_VERSION,
            extension_id: ExtensionId::new(),
            name: "dev.mealy.fixture".to_owned(),
            publisher: "dev.mealy".to_owned(),
            version: "1.0.0".to_owned(),
            kinds: BTreeSet::from([ExtensionKind::ToolService]),
            compatibility: ExtensionCompatibility {
                minimum_host_api: 1,
                maximum_host_api: 1,
            },
            entry_point: ExtensionEntryPoint {
                executable: "bin/worker".to_owned(),
                executable_digest: sha256_digest(worker),
                runtime_files: Vec::new(),
            },
            capabilities: vec![ExtensionCapabilityManifest {
                capability_id: "health".to_owned(),
                kind: ExtensionCapabilityKind::Health,
                effect_class: EffectClass::ReadOnly,
                risk_class: RiskClass::Low,
                input_schema: ExtensionObjectSchema {
                    properties: BTreeMap::new(),
                    required: BTreeSet::new(),
                    additional_properties: false,
                    maximum_serialized_bytes: 2,
                },
                output_schema: ExtensionObjectSchema {
                    properties: BTreeMap::from([(
                        "status".to_owned(),
                        ExtensionFieldSchema {
                            value_type: ExtensionScalarType::String,
                            maximum_length: Some(32),
                            minimum_integer: None,
                            maximum_integer: None,
                        },
                    )]),
                    required: BTreeSet::from(["status".to_owned()]),
                    additional_properties: false,
                    maximum_serialized_bytes: 64,
                },
                timeout_ms: 500,
                maximum_output_bytes: 1_024,
            }],
            permissions: ExtensionPermissions::default(),
            health_check: ExtensionHealthCheck {
                capability_id: "health".to_owned(),
                timeout_ms: 500,
                interval_ms: 1_000,
            },
            migrations: Vec::new(),
            shutdown: ExtensionShutdownBehavior {
                mode: ExtensionShutdownMode::Terminate,
                capability_id: None,
                grace_period_ms: 1_000,
            },
        }
    }
}
