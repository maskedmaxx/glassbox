use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub modified_at: String,
    pub mode: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ModifiedFile {
    pub path: String,
    pub before_size: u64,
    pub after_size: u64,
    pub before_mode: String,
    pub after_mode: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct FilesystemDiff {
    pub created: Vec<FileEntry>,
    pub modified: Vec<ModifiedFile>,
    pub deleted: Vec<FileEntry>,
}

impl FilesystemDiff {
    pub fn from_manifest_files(before: &Path, after: &Path) -> Result<Self> {
        let before_entries = parse_manifest(before)
            .with_context(|| format!("failed to parse {}", before.display()))?;
        let after_entries = parse_manifest(after)
            .with_context(|| format!("failed to parse {}", after.display()))?;

        Ok(Self::between(before_entries, after_entries))
    }

    pub fn between(before: Vec<FileEntry>, after: Vec<FileEntry>) -> Self {
        let before_by_path = index_by_path(before);
        let after_by_path = index_by_path(after);

        let mut created = Vec::new();
        let mut modified = Vec::new();
        let mut deleted = Vec::new();

        for (path, after_entry) in &after_by_path {
            match before_by_path.get(path) {
                Some(before_entry) if entry_changed(before_entry, after_entry) => {
                    modified.push(ModifiedFile {
                        path: path.clone(),
                        before_size: before_entry.size,
                        after_size: after_entry.size,
                        before_mode: before_entry.mode.clone(),
                        after_mode: after_entry.mode.clone(),
                    });
                }
                Some(_) => {}
                None => created.push(after_entry.clone()),
            }
        }

        for (path, before_entry) in &before_by_path {
            if !after_by_path.contains_key(path) {
                deleted.push(before_entry.clone());
            }
        }

        created.sort_by(|left, right| left.path.cmp(&right.path));
        modified.sort_by(|left, right| left.path.cmp(&right.path));
        deleted.sort_by(|left, right| left.path.cmp(&right.path));

        Self {
            created,
            modified,
            deleted,
        }
    }

    pub fn changed_file_count(&self) -> usize {
        self.created.len() + self.modified.len() + self.deleted.len()
    }
}

fn parse_manifest(path: &Path) -> Result<Vec<FileEntry>> {
    let contents = fs::read_to_string(path)?;
    let mut entries = Vec::new();

    for line in contents.lines() {
        if line.trim().is_empty() {
            continue;
        }

        let mut parts = line.splitn(5, '\t');
        let Some(path) = parts.next() else { continue };
        let Some(size) = parts.next() else { continue };
        let Some(modified_at) = parts.next() else {
            continue;
        };
        let Some(mode) = parts.next() else { continue };
        let Some(kind) = parts.next() else { continue };

        if should_ignore_path(path) {
            continue;
        }

        entries.push(FileEntry {
            path: path.to_string(),
            size: size.parse().unwrap_or_default(),
            modified_at: modified_at.to_string(),
            mode: mode.to_string(),
            kind: kind.to_string(),
        });
    }

    Ok(entries)
}

fn index_by_path(entries: Vec<FileEntry>) -> HashMap<String, FileEntry> {
    entries
        .into_iter()
        .map(|entry| (entry.path.clone(), entry))
        .collect()
}

fn entry_changed(before: &FileEntry, after: &FileEntry) -> bool {
    before.size != after.size
        || before.modified_at != after.modified_at
        || before.mode != after.mode
        || before.kind != after.kind
}

fn should_ignore_path(path: &str) -> bool {
    path.starts_with("/proc/")
        || path.starts_with("/sys/")
        || path.starts_with("/dev/")
        || path.starts_with("/run/")
        || path.starts_with("/tmp/")
        || path.starts_with("/glassbox-out/")
}

#[cfg(test)]
mod tests {
    use super::{FileEntry, FilesystemDiff};

    #[test]
    fn detects_created_modified_and_deleted_files() {
        let before = vec![
            entry("/same", 1, "1", "644", "f"),
            entry("/changed", 1, "1", "644", "f"),
            entry("/removed", 1, "1", "644", "f"),
        ];
        let after = vec![
            entry("/same", 1, "1", "644", "f"),
            entry("/changed", 2, "2", "644", "f"),
            entry("/created", 1, "1", "644", "f"),
        ];

        let diff = FilesystemDiff::between(before, after);

        assert_eq!(diff.created.len(), 1);
        assert_eq!(diff.created[0].path, "/created");
        assert_eq!(diff.modified.len(), 1);
        assert_eq!(diff.modified[0].path, "/changed");
        assert_eq!(diff.deleted.len(), 1);
        assert_eq!(diff.deleted[0].path, "/removed");
        assert_eq!(diff.changed_file_count(), 3);
    }

    fn entry(path: &str, size: u64, modified_at: &str, mode: &str, kind: &str) -> FileEntry {
        FileEntry {
            path: path.to_string(),
            size,
            modified_at: modified_at.to_string(),
            mode: mode.to_string(),
            kind: kind.to_string(),
        }
    }
}
