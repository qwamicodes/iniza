use std::collections::BTreeSet;
use std::ffi::{CString, OsString};
use std::fs::File;
use std::io;
use std::path::{Component, Path};

use cap_std::ambient_authority;
use cap_std::fs::{Dir, DirBuilder, DirBuilderExt, OpenOptions, OpenOptionsExt};

#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as StdPermissionsExt;

pub(crate) struct RestoreDirectory {
    directory: Dir,
}

impl RestoreDirectory {
    pub(crate) fn open_ambient(path: &Path) -> io::Result<Self> {
        Dir::open_ambient_dir(path, ambient_authority()).map(|directory| Self { directory })
    }

    pub(crate) fn reopen(&self) -> io::Result<Self> {
        Dir::reopen_dir(&self.directory).map(|directory| Self { directory })
    }

    pub(crate) fn open_dir(&self, relative_path: &Path) -> io::Result<Self> {
        #[cfg(unix)]
        {
            let mut options = OpenOptions::new();
            options
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
            self.directory
                .open_with(relative_path, &options)
                .map(cap_std::fs::File::into_std)
                .map(Dir::from_std_file)
                .map(|directory| Self { directory })
        }
        #[cfg(not(unix))]
        self.directory
            .open_dir(relative_path)
            .map(|directory| Self { directory })
    }

    pub(crate) fn create_restrictive_dir(&self, name: &Path) -> io::Result<()> {
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        self.directory.create_dir_with(name, &builder)
    }

    pub(crate) fn create_restrictive_dir_all(&self, relative_path: &Path) -> io::Result<()> {
        let mut current = self.reopen()?;
        for component in relative_path.components() {
            let Component::Normal(name) = component else {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Restore directory path is not relative",
                ));
            };
            match current.create_restrictive_dir(Path::new(name)) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    if !current.directory.symlink_metadata(name)?.is_dir() {
                        return Err(io::Error::new(
                            io::ErrorKind::AlreadyExists,
                            "Restore directory path conflicts with another filesystem item",
                        ));
                    }
                }
                Err(error) => return Err(error),
            }
            current = current.open_dir(Path::new(name))?;
        }
        Ok(())
    }

    pub(crate) fn entry_names(&self, max_entries: usize) -> io::Result<Vec<OsString>> {
        let mut names = Vec::new();
        for entry in self.directory.entries()? {
            names.push(entry?.file_name());
            if names.len() > max_entries {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Restore directory exceeds its entry limit",
                ));
            }
        }
        Ok(names)
    }

    pub(crate) fn is_empty(&self) -> io::Result<bool> {
        self.directory
            .entries()?
            .next()
            .transpose()
            .map(|entry| entry.is_none())
    }

    pub(crate) fn relative_entries(
        &self,
        max_entries: usize,
        max_depth: usize,
    ) -> io::Result<BTreeSet<std::path::PathBuf>> {
        let mut entries = BTreeSet::new();
        let mut pending = vec![(std::path::PathBuf::new(), 0_usize)];
        while let Some((prefix, depth)) = pending.pop() {
            let directory = if prefix.as_os_str().is_empty() {
                self.reopen()?
            } else {
                self.open_dir(&prefix)?
            };
            for entry in directory.directory.entries()? {
                let name = entry?.file_name();
                let entry_depth = depth.checked_add(1).ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "Restore tree depth overflowed")
                })?;
                if entry_depth > max_depth {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Restore tree exceeds its depth limit",
                    ));
                }
                let relative_path = prefix.join(&name);
                let metadata = directory.symlink_metadata(Path::new(&name))?;
                entries.insert(relative_path.clone());
                if entries.len() > max_entries {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Restore tree exceeds its entry limit",
                    ));
                }
                if metadata.is_dir() {
                    pending.push((relative_path, entry_depth));
                }
            }
        }
        Ok(entries)
    }

    pub(crate) fn symlink_metadata(
        &self,
        relative_path: &Path,
    ) -> io::Result<cap_std::fs::Metadata> {
        self.directory.symlink_metadata(relative_path)
    }

    pub(crate) fn read_link(&self, relative_path: &Path) -> io::Result<std::path::PathBuf> {
        self.directory.read_link_contents(relative_path)
    }

    pub(crate) fn remove_dir_all(&self, relative_path: &Path) -> io::Result<()> {
        self.directory.remove_dir_all(relative_path)
    }

    pub(crate) fn remove_dir(&self, relative_path: &Path) -> io::Result<()> {
        self.directory.remove_dir(relative_path)
    }

    pub(crate) fn remove_file(&self, relative_path: &Path) -> io::Result<()> {
        self.directory.remove_file(relative_path)
    }

    #[cfg(unix)]
    pub(crate) fn set_mode_nofollow(&self, relative_path: &Path, mode: u32) -> io::Result<()> {
        let parent_path = relative_path.parent().unwrap_or_else(|| Path::new(""));
        let parent = if parent_path.as_os_str().is_empty() {
            self.reopen()?
        } else {
            self.open_dir(parent_path)?
        };
        let name = relative_path.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Restore metadata path has no final component",
            )
        })?;
        let name = CString::new(name.as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains null"))?;
        // SAFETY: `name` is a live null-terminated final component, the parent
        // directory descriptor remains open, and AT_SYMLINK_NOFOLLOW prevents
        // a substituted final symbolic link from redirecting the mode change.
        let result = unsafe {
            libc::fchmodat(
                parent.directory.as_raw_fd(),
                name.as_ptr(),
                (mode & 0o7777) as libc::mode_t,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    pub(crate) fn open_file(&self, relative_path: &Path) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW);
        self.directory
            .open_with(relative_path, &options)
            .map(cap_std::fs::File::into_std)
    }

    pub(crate) fn open_file_for_write(&self, relative_path: &Path) -> io::Result<File> {
        let mut options = OpenOptions::new();
        options.write(true);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW);
        self.directory
            .open_with(relative_path, &options)
            .map(cap_std::fs::File::into_std)
    }

    pub(crate) fn metadata_file(&self, relative_path: &Path) -> io::Result<File> {
        if relative_path.as_os_str().is_empty() {
            return self.reopen().map(Self::into_file);
        }
        let metadata = self.symlink_metadata(relative_path)?;
        if metadata.is_dir() {
            self.open_dir(relative_path).map(Self::into_file)
        } else if metadata.is_file() {
            self.open_file(relative_path)
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "metadata application to symbolic links is unsupported",
            ))
        }
    }

    pub(crate) fn into_file(self) -> File {
        self.directory.into_std_file()
    }

    pub(crate) fn sync(&self) -> io::Result<()> {
        self.reopen()?.into_file().sync_all()
    }

    pub(crate) fn metadata(&self) -> io::Result<std::fs::Metadata> {
        self.reopen()?.into_file().metadata()
    }

    pub(crate) fn rename(&self, from: &Path, destination: &Self, to: &Path) -> io::Result<()> {
        self.directory.rename(from, &destination.directory, to)
    }

    pub(crate) fn exclusive_rename(
        &self,
        from: &Path,
        destination: &Self,
        to: &Path,
    ) -> io::Result<()> {
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        {
            let from = CString::new(from.as_os_str().as_bytes())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains null"))?;
            let to = CString::new(to.as_os_str().as_bytes())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains null"))?;
            #[cfg(target_os = "macos")]
            // SAFETY: both paths are live null-terminated strings, both directory
            // descriptors remain open for the call, and RENAME_EXCL prevents overwrite.
            let result = unsafe {
                libc::renameatx_np(
                    self.directory.as_raw_fd(),
                    from.as_ptr(),
                    destination.directory.as_raw_fd(),
                    to.as_ptr(),
                    libc::RENAME_EXCL,
                )
            };
            #[cfg(target_os = "linux")]
            // SAFETY: both paths are live null-terminated strings, both directory
            // descriptors remain open for the call, and RENAME_NOREPLACE prevents overwrite.
            let result = unsafe {
                libc::renameat2(
                    self.directory.as_raw_fd(),
                    from.as_ptr(),
                    destination.directory.as_raw_fd(),
                    to.as_ptr(),
                    libc::RENAME_NOREPLACE,
                )
            };
            if result == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = (from, destination, to);
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "atomic no-replace Restore publication is unsupported on this platform",
            ))
        }
    }

    pub(crate) fn create_restricted_file(&self, relative_path: &Path) -> io::Result<File> {
        let parent_path = relative_path.parent().unwrap_or_else(|| Path::new(""));
        let parent = if parent_path.as_os_str().is_empty() {
            self.reopen()?
        } else {
            self.open_dir(parent_path)?
        };
        let name = relative_path.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Restore file path has no final component",
            )
        })?;
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        #[cfg(unix)]
        options.custom_flags(libc::O_NOFOLLOW);
        let file = parent
            .directory
            .open_with(Path::new(name), &options)
            .map(cap_std::fs::File::into_std)?;
        #[cfg(unix)]
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
        Ok(file)
    }

    #[cfg(unix)]
    pub(crate) fn create_symlink(&self, target: &Path, relative_path: &Path) -> io::Result<()> {
        let parent_path = relative_path.parent().unwrap_or_else(|| Path::new(""));
        let parent = if parent_path.as_os_str().is_empty() {
            self.reopen()?
        } else {
            self.open_dir(parent_path)?
        };
        let name = relative_path.file_name().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Restore symbolic-link path has no final component",
            )
        })?;
        parent.directory.symlink_contents(target, Path::new(name))
    }
}
