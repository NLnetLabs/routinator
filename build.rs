//! Build script.
//!
//! This script collects the assets for serving the Routinator UI and creates
//! a module for them in `$OUT_DIR/ui_assets.rs`.
//!
//! If built without the ui feature, does nothing.
use std::{env, fs, io, process};
use std::path::{PathBuf, Path};


const UI_DIR: &str = "contrib/ui";
const RS_FILE: &str = "ui_assets.rs";

const TYPES: &[(&str, &str)] = &[
    ("css", "text/css"),
    ("html", "text/html"),
    ("js", "text/javascript"),
    ("svg", "image/svg+xml")
];

struct Asset {
    path: PathBuf,
    media_type: &'static str,
    content: Vec<u8>,
}

#[derive(Default)]
struct Assets(Vec<Asset>);

impl Assets {
    fn load_dir(&mut self, path: PathBuf) -> Result<(), String> {
        let dir = fs::read_dir(&path).map_err(|err| {
            format!("Failed to open directory {}: {}", path.display(), err)
        })?;
        for entry in dir {
            let entry = entry.map_err(|err| {
                format!("Failed to read directory {}: {}", path.display(), err)
            })?;
            let path = entry.path();
            if path.is_dir() {
                self.load_dir(path)?;
            }
            else {
                let path_ext = match path.extension().and_then(|s| s.to_str()) {
                    Some(ext) => ext,
                    None => continue,
                };
                for (type_ext, media_type) in TYPES {
                    if path_ext == *type_ext {
                        self.0.push(Asset {
                            path: path.strip_prefix(UI_DIR).map_err(|_| {
                                format!("Asset path {} not under {}",
                                    path.display(), UI_DIR
                                )
                            })?.into(),
                            media_type,
                            content: fs::read(&path).map_err(|err| {
                                format!(
                                    "Failed to read UI asset file {}: {}.",
                                    path.display(), err
                                )
                            })?
                        })
                    }
                }
            }
        }
        Ok(())
    }

    fn write_mod(self, dest: &mut impl io::Write) -> Result<(), io::Error> {
        dest.write_all(
            r#"
            pub struct Asset {
                pub path: &'static str,
                pub media_type: &'static str,
                pub content: &'static [u8],
            }

            pub static ASSETS: &[Asset] = &[
            "#.as_ref()
        )?;
        for item in self.0 {
            writeln!(dest,
                "
                Asset {{
                    path: r#\"{}\"#,
                    media_type: \"{}\",
                    content: &{:?},
                }},
                ",
                item.path.display(),
                item.media_type,
                item.content.as_slice(),
            )?;
        }
        writeln!(dest, "];")
    }
}


fn main() {
    if env::var_os("CARGO_FEATURE_UI").is_none() {
        return
    }

    let out_dir = env::var_os("OUT_DIR").unwrap_or_default();
    let target_path = Path::new(&out_dir).join(RS_FILE);
    let mut target = match fs::File::create(&target_path) {
        Ok(target) => io::BufWriter::new(target),
        Err(err) => {
            eprintln!("Failed to open assets module file {}: {}",
                target_path.display(), err
            );
            process::exit(1);
        }
    };

    let mut assets = Assets::default();
    if let Err(err) = assets.load_dir(UI_DIR.into()) {
        eprintln!("{}", err);
        process::exit(1);
    }

    if let Err(err) = assets.write_mod(&mut target) {
        eprintln!("Failed to write to assets module file {}: {}",
            target_path.display(), err
        );
        process::exit(1)
    }

    println!("cargo:rerun-if-changed={}", UI_DIR);
}

