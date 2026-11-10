use std::fs::File;
use std::io::Read;
use std::path::{Component, Path};

use flate2::read::GzDecoder;
use tar::Archive;

const MAX_ENTRIES: usize = 50_000;
const MAX_PATH_LEN: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleFormat {
    Tar,
    TarGz,
}

impl BundleFormat {
    pub fn extension(self) -> &'static str {
        match self {
            BundleFormat::Tar => "tar",
            BundleFormat::TarGz => "tar.gz",
        }
    }
}

/// Facts about a bundle that passed validation. The caller stores these so a
/// report can say what was actually run.
#[derive(Debug, Clone)]
pub struct BundleInfo {
    pub files: usize,
    pub unpacked_bytes: u64,
    pub has_trident_tests: bool,
}

pub fn detect_format(path: &Path) -> std::io::Result<BundleFormat> {
    let mut magic = [0u8; 2];
    let mut file = File::open(path)?;
    let read = file.read(&mut magic)?;
    Ok(if read == 2 && magic == [0x1f, 0x8b] {
        BundleFormat::TarGz
    } else {
        BundleFormat::Tar
    })
}

/// Validate an uploaded archive without extracting it.
///
/// This is a cheap first line of defense, not a sandbox: it rejects path
/// traversal, links, devices, oversized expansions, and bundles that do not
/// look like an Anchor workspace. The actual untrusted execution happens in
/// the worker's container.
pub fn validate(
    path: &Path,
    format: BundleFormat,
    max_unpacked_bytes: u64,
) -> Result<BundleInfo, String> {
    let file = File::open(path).map_err(|e| format!("cannot open bundle: {e}"))?;

    // Cap decompression even if the tar headers lie about entry sizes.
    let reader: Box<dyn Read> = match format {
        BundleFormat::Tar => Box::new(file),
        BundleFormat::TarGz => Box::new(GzDecoder::new(file)),
    };
    let limited = reader.take(max_unpacked_bytes.saturating_add(16 * 1024 * 1024));
    let mut archive = Archive::new(limited);

    let mut file_paths: Vec<String> = Vec::new();
    let mut unpacked_bytes: u64 = 0;
    let mut entry_count: usize = 0;

    let entries = archive
        .entries()
        .map_err(|e| format!("not a readable tar archive: {e}"))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("invalid archive entry: {e}"))?;
        entry_count += 1;
        if entry_count > MAX_ENTRIES {
            return Err(format!("bundle has more than {MAX_ENTRIES} entries"));
        }

        let kind = entry.header().entry_type();
        // Only regular files and directories. This rejects symlinks, hard
        // links, device nodes, FIFOs, and tar metadata entries.
        if !(kind.is_file() || kind.is_dir()) {
            return Err(format!("unsupported archive entry type: {kind:?}"));
        }

        let raw_path = entry
            .path()
            .map_err(|e| format!("invalid entry path: {e}"))?;
        validate_components(&raw_path)?;

        let normalized = normalize(&raw_path);
        if normalized.is_empty() {
            continue;
        }
        if normalized.len() > MAX_PATH_LEN {
            return Err(format!("entry path is longer than {MAX_PATH_LEN} bytes"));
        }

        let size = entry.header().size().unwrap_or(0);
        unpacked_bytes = unpacked_bytes
            .checked_add(size)
            .ok_or_else(|| "bundle size overflow".to_string())?;
        if unpacked_bytes > max_unpacked_bytes {
            return Err(format!(
                "bundle expands to more than the {max_unpacked_bytes} byte limit"
            ));
        }

        if kind.is_file() {
            file_paths.push(normalized);
        }
    }

    if file_paths.is_empty() {
        return Err("bundle contains no files".into());
    }

    // Accept either a project at the archive root or a project wrapped in a
    // single directory (the usual `tar czf bundle.tgz my-project` shape).
    let strip_prefix = common_wrapper(&file_paths);
    let mut stripped: Vec<String> = Vec::with_capacity(file_paths.len());
    for path in &file_paths {
        match &strip_prefix {
            Some(prefix) => {
                if let Some(rest) = path.strip_prefix(&format!("{prefix}/")) {
                    if !rest.is_empty() {
                        stripped.push(rest.to_string());
                    }
                }
            }
            None => stripped.push(path.clone()),
        }
    }

    let has_anchor = stripped.iter().any(|p| p == "Anchor.toml");
    if !has_anchor {
        return Err("bundle must contain an Anchor.toml at the project root".into());
    }

    let has_program = stripped
        .iter()
        .any(|p| p.starts_with("programs/") && p.ends_with(".rs"));
    if !has_program {
        return Err("bundle must contain a Rust program under programs/".into());
    }

    let has_trident_tests = stripped
        .iter()
        .any(|p| p.starts_with("trident-tests/") && p.ends_with(".rs"));

    Ok(BundleInfo {
        files: file_paths.len(),
        unpacked_bytes,
        has_trident_tests,
    })
}

fn validate_components(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("archive contains an empty path".into());
    }
    for component in path.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            _ => return Err(format!("unsafe path in archive: {}", path.display())),
        }
    }
    Ok(())
}

fn normalize(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_string_lossy().into_owned()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// If every file lives under one top-level directory, `tar czf x.tgz dir`
/// was used. Return that directory so validation and the sandbox agree on
/// where the project root is.
fn common_wrapper(paths: &[String]) -> Option<String> {
    if paths.iter().any(|p| p == "Anchor.toml") {
        return None;
    }
    let first = paths.first()?.split('/').next()?.to_string();
    if paths
        .iter()
        .all(|p| p == &first || p.starts_with(&format!("{first}/")))
    {
        Some(first)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tar::{Builder, EntryType, Header};

    fn tar_with(entries: &[(&str, Option<&[u8]>)]) -> Vec<u8> {
        let mut builder = Builder::new(Vec::new());
        for (path, data) in entries {
            match data {
                Some(bytes) => {
                    let mut header = Header::new_gnu();
                    header.set_size(bytes.len() as u64);
                    header.set_mode(0o644);
                    header.set_cksum();
                    builder
                        .append_data(&mut header, path, Cursor::new(bytes))
                        .unwrap();
                }
                None => {
                    let mut header = Header::new_gnu();
                    header.set_size(0);
                    header.set_mode(0o755);
                    header.set_entry_type(EntryType::Directory);
                    header.set_cksum();
                    builder
                        .append_data(&mut header, path, Cursor::new(Vec::new()))
                        .unwrap();
                }
            }
        }
        builder.into_inner().unwrap()
    }

    fn validate_bytes(bytes: Vec<u8>) -> Result<BundleInfo, String> {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bundle.tar");
        std::fs::write(&path, bytes).unwrap();
        validate(&path, BundleFormat::Tar, 64 * 1024 * 1024)
    }

    /// `tar::Builder` refuses to write `..` paths, which is good — so build a
    /// raw ustar block by hand to test that the *reader* rejects it too.
    fn raw_tar_entry(name: &str, data: &[u8]) -> Vec<u8> {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..108].copy_from_slice(b"0000644\0");
        header[108..116].copy_from_slice(b"0000000\0");
        header[116..124].copy_from_slice(b"0000000\0");
        header[124..136].copy_from_slice(format!("{:011o}\0", data.len()).as_bytes());
        header[136..148].copy_from_slice(b"00000000000\0");
        header[148..156].copy_from_slice(b"        ");
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");

        let checksum: u32 = header.iter().map(|byte| *byte as u32).sum();
        header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());

        let mut block = header.to_vec();
        block.extend_from_slice(data);
        let padding = (512 - data.len() % 512) % 512;
        block.resize(block.len() + padding, 0);
        block
    }

    #[test]
    fn accepts_anchor_project() {
        let bytes = tar_with(&[
            ("Anchor.toml", Some(b"[programs.localnet]\n")),
            ("programs/demo/src/lib.rs", Some(b"pub fn demo() {}\n")),
            ("programs/demo/Cargo.toml", Some(b"[package]\n")),
        ]);
        let info = validate_bytes(bytes).unwrap();
        assert_eq!(info.files, 3);
        assert!(!info.has_trident_tests);
    }

    #[test]
    fn accepts_project_wrapped_in_a_directory() {
        let bytes = tar_with(&[
            ("demo/Anchor.toml", Some(b"[programs.localnet]\n")),
            ("demo/programs/demo/src/lib.rs", Some(b"pub fn demo() {}\n")),
        ]);
        assert!(validate_bytes(bytes).is_ok());
    }

    #[test]
    fn rejects_missing_anchor_toml() {
        let bytes = tar_with(&[("programs/demo/src/lib.rs", Some(b"pub fn demo() {}\n"))]);
        let err = validate_bytes(bytes).unwrap_err();
        assert!(err.contains("Anchor.toml"), "{err}");
    }

    #[test]
    fn rejects_path_traversal() {
        let lib = b"pub fn demo() {}\n";
        let toml = b"[programs.localnet]\n";
        let mut bytes = Vec::new();
        bytes.extend(raw_tar_entry("Anchor.toml", toml));
        bytes.extend(raw_tar_entry("programs/demo/src/lib.rs", lib));
        bytes.extend(raw_tar_entry("../../etc/passwd", b"nope"));
        bytes.extend([0u8; 1024]);
        let err = validate_bytes(bytes).unwrap_err();
        assert!(err.contains("unsafe path"), "{err}");
    }

    #[test]
    fn rejects_symlinks() {
        let mut builder = Builder::new(Vec::new());
        let toml = b"[programs.localnet]\n";
        let mut header = Header::new_gnu();
        header.set_size(toml.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "Anchor.toml", Cursor::new(toml))
            .unwrap();

        let lib = b"pub fn demo() {}\n";
        let mut header = Header::new_gnu();
        header.set_size(lib.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "programs/demo/src/lib.rs", Cursor::new(lib))
            .unwrap();

        let mut link = Header::new_gnu();
        link.set_size(0);
        link.set_mode(0o777);
        link.set_entry_type(EntryType::Symlink);
        link.set_link_name("/etc/passwd").unwrap();
        link.set_cksum();
        builder
            .append_data(&mut link, "programs/demo/src/evil", Cursor::new(Vec::new()))
            .unwrap();

        assert!(validate_bytes(builder.into_inner().unwrap()).is_err());
    }
}
