use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

const MAX_EXTENDED_ATTRIBUTE_COUNT: usize = 128;
const MAX_EXTENDED_ATTRIBUTE_NAME: usize = 1_024;
const MAX_EXTENDED_ATTRIBUTE_VALUE: usize = 1024 * 1024;
const MAX_EXTENDED_ATTRIBUTE_TOTAL: usize = 4 * 1024 * 1024;
const MAX_ACCESS_CONTROL_TEXT: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtendedAttribute {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

#[cfg(target_os = "macos")]
mod macos {
    use std::ffi::{CStr, CString, c_char, c_int, c_void};
    use std::os::unix::ffi::OsStrExt;
    use std::ptr;

    use super::*;

    const ACCESS_CONTROL_TYPE_EXTENDED: c_int = 0x0000_0100;

    unsafe extern "C" {
        fn acl_get_file(path: *const c_char, access_control_type: c_int) -> *mut c_void;
        fn acl_get_link_np(path: *const c_char, access_control_type: c_int) -> *mut c_void;
        fn acl_set_file(
            path: *const c_char,
            access_control_type: c_int,
            access_control: *mut c_void,
        ) -> c_int;
        fn acl_set_link_np(
            path: *const c_char,
            access_control_type: c_int,
            access_control: *mut c_void,
        ) -> c_int;
        fn acl_from_text(text: *const c_char) -> *mut c_void;
        fn acl_to_text(access_control: *mut c_void, length: *mut isize) -> *mut c_char;
        fn acl_free(object: *mut c_void) -> c_int;
    }

    pub(super) fn read_extended_attributes(
        path: &Path,
        no_follow: bool,
    ) -> io::Result<Vec<ExtendedAttribute>> {
        let path = c_path(path)?;
        let options = if no_follow { libc::XATTR_NOFOLLOW } else { 0 };
        // SAFETY: `path` is a live null-terminated string. A null output buffer
        // asks the operating system for the required list length.
        let list_length = unsafe { libc::listxattr(path.as_ptr(), ptr::null_mut(), 0, options) };
        if list_length < 0 {
            return Err(io::Error::last_os_error());
        }
        if list_length == 0 {
            return Ok(Vec::new());
        }
        let mut names = vec![0_u8; list_length as usize];
        // SAFETY: `names` exposes exactly `names.len()` writable bytes and the
        // other arguments remain live for the duration of the call.
        let read = unsafe {
            libc::listxattr(
                path.as_ptr(),
                names.as_mut_ptr().cast(),
                names.len(),
                options,
            )
        };
        if read < 0 || read as usize != names.len() {
            return Err(io::Error::last_os_error());
        }
        let mut attributes = Vec::new();
        let mut total = 0_usize;
        for name in names
            .split(|byte| *byte == 0)
            .filter(|name| !name.is_empty())
        {
            if attributes.len() >= MAX_EXTENDED_ATTRIBUTE_COUNT
                || name.len() > MAX_EXTENDED_ATTRIBUTE_NAME
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "extended metadata exceeds its capture limit",
                ));
            }
            let name_string = CString::new(name).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "extended attribute name contains a null byte",
                )
            })?;
            // SAFETY: the path and attribute name are live null-terminated
            // strings. A null value pointer requests the required value length.
            let value_length = unsafe {
                libc::getxattr(
                    path.as_ptr(),
                    name_string.as_ptr(),
                    ptr::null_mut(),
                    0,
                    0,
                    options,
                )
            };
            if value_length < 0 {
                return Err(io::Error::last_os_error());
            }
            if value_length as usize > MAX_EXTENDED_ATTRIBUTE_VALUE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "extended attribute value exceeds its capture limit",
                ));
            }
            let mut value = vec![0_u8; value_length as usize];
            if !value.is_empty() {
                // SAFETY: `value` exposes exactly `value.len()` writable bytes;
                // both C strings and the output buffer remain live.
                let value_read = unsafe {
                    libc::getxattr(
                        path.as_ptr(),
                        name_string.as_ptr(),
                        value.as_mut_ptr().cast(),
                        value.len(),
                        0,
                        options,
                    )
                };
                if value_read < 0 || value_read as usize != value.len() {
                    return Err(io::Error::last_os_error());
                }
            }
            total = total
                .checked_add(name.len())
                .and_then(|length| length.checked_add(value.len()))
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "extended metadata overflowed")
                })?;
            if total > MAX_EXTENDED_ATTRIBUTE_TOTAL {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "extended metadata exceeds its total capture limit",
                ));
            }
            attributes.push(ExtendedAttribute {
                name: name.to_vec(),
                value,
            });
        }
        attributes.sort_by(|left, right| left.name.cmp(&right.name));
        Ok(attributes)
    }

    pub(super) fn write_extended_attributes(
        path: &Path,
        no_follow: bool,
        attributes: &[ExtendedAttribute],
    ) -> io::Result<()> {
        validate_extended_attributes(attributes)?;
        let path = c_path(path)?;
        let options = if no_follow { libc::XATTR_NOFOLLOW } else { 0 };
        for attribute in attributes {
            let name = CString::new(attribute.name.as_slice()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "extended attribute name contains a null byte",
                )
            })?;
            // SAFETY: both C strings are live and `attribute.value` exposes the
            // declared readable byte range for the duration of the call.
            if unsafe {
                libc::setxattr(
                    path.as_ptr(),
                    name.as_ptr(),
                    attribute.value.as_ptr().cast(),
                    attribute.value.len(),
                    0,
                    options,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    pub(super) fn read_access_control(path: &Path, no_follow: bool) -> io::Result<Option<String>> {
        let path = c_path(path)?;
        // SAFETY: `path` is a live null-terminated string and the returned
        // access-control object is released below.
        let access_control = unsafe {
            if no_follow {
                acl_get_link_np(path.as_ptr(), ACCESS_CONTROL_TYPE_EXTENDED)
            } else {
                acl_get_file(path.as_ptr(), ACCESS_CONTROL_TYPE_EXTENDED)
            }
        };
        if access_control.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOENT) {
                return Ok(None);
            }
            return Err(error);
        }
        let mut length = 0_isize;
        // SAFETY: `access_control` is live and owned by this function; `length`
        // points to writable storage. Both returned objects are freed below.
        let text = unsafe { acl_to_text(access_control, &mut length) };
        if text.is_null() || length < 0 || length as usize > MAX_ACCESS_CONTROL_TEXT {
            // SAFETY: the access-control object was returned by `acl_get_*`.
            unsafe { acl_free(access_control) };
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "access-control metadata exceeds its capture limit",
            ));
        }
        // SAFETY: `acl_to_text` returns a null-terminated string while `text`
        // remains live. The length bound above limits copied data.
        let value = unsafe { CStr::from_ptr(text) }
            .to_str()
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "access-control metadata is not UTF-8",
                )
            })?
            .to_owned();
        // SAFETY: both objects were allocated by the access-control library.
        unsafe {
            acl_free(text.cast());
            acl_free(access_control);
        }
        Ok(if value.trim().is_empty() {
            None
        } else {
            Some(value)
        })
    }

    pub(super) fn write_access_control(path: &Path, no_follow: bool, text: &str) -> io::Result<()> {
        if text.len() > MAX_ACCESS_CONTROL_TEXT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "access-control metadata exceeds its apply limit",
            ));
        }
        let path = c_path(path)?;
        let text = CString::new(text).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "access-control metadata contains a null byte",
            )
        })?;
        // SAFETY: `text` is a live null-terminated access-control string. The
        // returned object is released below.
        let access_control = unsafe { acl_from_text(text.as_ptr()) };
        if access_control.is_null() {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: both path and access-control objects are live and valid for
        // the duration of this call.
        let result = unsafe {
            if no_follow {
                acl_set_link_np(path.as_ptr(), ACCESS_CONTROL_TYPE_EXTENDED, access_control)
            } else {
                acl_set_file(path.as_ptr(), ACCESS_CONTROL_TYPE_EXTENDED, access_control)
            }
        };
        // SAFETY: the object was allocated by `acl_from_text`.
        unsafe { acl_free(access_control) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    fn c_path(path: &Path) -> io::Result<CString> {
        CString::new(path.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "path contains a null byte"))
    }
}

pub(crate) fn read_extended_attributes(
    path: &Path,
    no_follow: bool,
) -> io::Result<Vec<ExtendedAttribute>> {
    #[cfg(target_os = "macos")]
    return macos::read_extended_attributes(path, no_follow);
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (path, no_follow);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "extended attributes are unsupported by this platform adapter",
        ))
    }
}

pub(crate) fn write_extended_attributes(
    path: &Path,
    no_follow: bool,
    attributes: &[ExtendedAttribute],
) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    return macos::write_extended_attributes(path, no_follow, attributes);
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (path, no_follow, attributes);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "extended attributes are unsupported by this platform adapter",
        ))
    }
}

pub(crate) fn read_access_control(path: &Path, no_follow: bool) -> io::Result<Option<String>> {
    #[cfg(target_os = "macos")]
    return macos::read_access_control(path, no_follow);
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (path, no_follow);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "access-control metadata is unsupported by this platform adapter",
        ))
    }
}

pub(crate) fn write_access_control(path: &Path, no_follow: bool, text: &str) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    return macos::write_access_control(path, no_follow, text);
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (path, no_follow, text);
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "access-control metadata is unsupported by this platform adapter",
        ))
    }
}

fn validate_extended_attributes(attributes: &[ExtendedAttribute]) -> io::Result<()> {
    if attributes.len() > MAX_EXTENDED_ATTRIBUTE_COUNT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "extended metadata exceeds its apply count limit",
        ));
    }
    let mut total = 0_usize;
    for attribute in attributes {
        if attribute.name.is_empty()
            || attribute.name.len() > MAX_EXTENDED_ATTRIBUTE_NAME
            || attribute.value.len() > MAX_EXTENDED_ATTRIBUTE_VALUE
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "extended metadata exceeds its apply limit",
            ));
        }
        total = total
            .checked_add(attribute.name.len())
            .and_then(|length| length.checked_add(attribute.value.len()))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "extended metadata overflowed")
            })?;
    }
    if total > MAX_EXTENDED_ATTRIBUTE_TOTAL {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "extended metadata exceeds its total apply limit",
        ));
    }
    Ok(())
}
