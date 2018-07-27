//! Rsync procession.

use std::{fmt, io, process, str};
use std::fs::create_dir_all;
use std::path::Path;
use bytes::{BufMut, Bytes, BytesMut};


//------------ Command -------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Command {
    has_contimeout: bool
}

impl Command {
    pub fn detect() -> Result<Command, DetectError> {
        let output = process::Command::new("rsync").arg("-h").output()?;
        if !output.status.success() {
            return Err(DetectError::Output(
                String::from_utf8_lossy(&output.stderr).into()
            ))
        }
        Ok(Command {
            has_contimeout:
                output.stdout.windows(12)
                             .any(|window| window == b"--contimeout")
        })
    }

    pub fn update<P: AsRef<Path>>(
        &self,
        source: &Module,
        destination: P
    ) -> Result<(), io::Error> {
        debug!("rsyncing from {}.", source);
        let destination = destination.as_ref();
        create_dir_all(destination)?;
        let mut destination = format!("{}", destination.display());
        if !destination.ends_with("/") {
            destination.push('/')
        }
        let mut cmd = process::Command::new("rsync");
        cmd.arg("-az")
           .arg("--delete");
        if self.has_contimeout {
            cmd.arg("--contimeout=10");
        }
        cmd.arg(source.to_string())
           .arg(destination);
        debug!("Running {:?}", cmd);
        if !cmd.status()?.success() {
            return Err(io::Error::new(io::ErrorKind::Other, "rsync failed"))
        }
        Ok(())
    }
}


//------------ DetectError ---------------------------------------------------

#[derive(Debug, Fail)]
pub enum DetectError {
    #[fail(display="unable to run rsync:\n{}", _0)]
    Command(io::Error),

    #[fail(display="unable to run rsync:\n{}", _0)]
    Output(String),
}

impl From<io::Error> for DetectError {
    fn from(err: io::Error) -> DetectError {
        DetectError::Command(err)
    }
}

