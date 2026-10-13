use crate::prelude::*;

use std::io::{Read as _, Write as _};

use is_terminal::IsTerminal as _;

pub fn edit(contents: &str, help: &str, ext: &str) -> Result<String> {
    if !std::io::stdin().is_terminal() {
        // directly read from piped content
        return match std::io::read_to_string(std::io::stdin()) {
            Err(e) => Err(Error::FailedToReadFromStdin { err: e }),
            Ok(res) => Ok(res),
        };
    }

    let mut var = "VISUAL";
    let editor = std::env::var_os(var).unwrap_or_else(|| {
        var = "EDITOR";
        std::env::var_os(var).unwrap_or_else(|| "/usr/bin/vim".into())
    });

    let dir = tempfile::tempdir().unwrap();
    let filename = if ext.is_empty() {
        "rbw".to_string()
    } else {
        format!("rbw.{ext}")
    };
    let file = dir.path().join(filename);
    let mut fh = std::fs::File::create(&file).unwrap();
    if !help.is_empty() {
        fh.write_all(help.as_bytes()).unwrap();
        fh.write_all(b"\n").unwrap();
    }
    fh.write_all(contents.as_bytes()).unwrap();
    drop(fh);

    let (cmd, args) = if contains_shell_metacharacters(&editor) {
        let mut cmdline = std::ffi::OsString::new();
        cmdline.extend([
            editor.as_ref(),
            std::ffi::OsStr::new(" "),
            file.as_os_str(),
        ]);

        let editor_args = vec![std::ffi::OsString::from("-c"), cmdline];
        (std::path::Path::new("/bin/sh"), editor_args)
    } else {
        let editor = std::path::Path::new(&editor);
        let mut editor_args = vec![];

        #[allow(clippy::single_match_else)] // more to come
        match editor.file_name() {
            Some(editor) => match editor.to_str() {
                Some("vim" | "nvim") => {
                    // disable swap files and viminfo for password entry
                    editor_args.push(std::ffi::OsString::from("-ni"));
                    editor_args.push(std::ffi::OsString::from("NONE"));
                }
                _ => {
                    // other editor support welcomed
                }
            },
            None => {
                return Err(Error::InvalidEditor {
                    var: var.to_string(),
                    editor: editor.as_os_str().to_os_string(),
                })
            }
        }
        editor_args.push(file.clone().into_os_string());
        (editor, editor_args)
    };

    let res = std::process::Command::new(cmd).args(&args).status();
    match res {
        Ok(res) => {
            if !res.success() {
                return Err(Error::FailedToRunEditor {
                    editor: cmd.to_owned(),
                    args,
                    res,
                });
            }
        }
        Err(err) => {
            return Err(Error::FailedToFindEditor {
                editor: cmd.to_owned(),
                err,
            })
        }
    }

    let mut fh = std::fs::File::open(&file).unwrap();
    let mut contents = String::new();
    fh.read_to_string(&mut contents).unwrap();
    drop(fh);

    Ok(contents)
}

fn contains_shell_metacharacters(cmd: &std::ffi::OsStr) -> bool {
    cmd.to_str()
        .is_some_and(|s| s.contains(&[' ', '$', '\'', '"'][..]))
}

/// Retain only interactive edits. Piped credentials must never reach this path.
pub fn save_unsaved(contents: &str) -> Result<std::path::PathBuf> {
    save_unsaved_in(&crate::dirs::unsaved_edit_dir(), contents)
}

fn save_unsaved_in(
    dir: &std::path::Path,
    contents: &str,
) -> Result<std::path::PathBuf> {
    crate::dirs::create_dir_all_with_permissions(dir, 0o700)?;
    let mut file = tempfile::Builder::new()
        .prefix("unsaved-")
        .suffix(".txt")
        .tempfile_in(dir)
        .map_err(|err| Error::UnsavedEdit { source: err })?;
    file.write_all(contents.as_bytes())
        .map_err(|err| Error::UnsavedEdit { source: err })?;
    file.as_file()
        .sync_all()
        .map_err(|err| Error::UnsavedEdit { source: err })?;
    file.keep()
        .map(|(_, path)| path)
        .map_err(|err| Error::UnsavedEdit { source: err.error })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn recovery_files_are_private_unique_and_complete() {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().join("unsaved");
        let first = save_unsaved_in(&dir, "first edit").unwrap();
        let second = save_unsaved_in(&dir, "second edit").unwrap();
        assert_ne!(first, second);
        assert_eq!(std::fs::read_to_string(&first).unwrap(), "first edit");
        assert_eq!(std::fs::read_to_string(&second).unwrap(), "second edit");
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&first).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
