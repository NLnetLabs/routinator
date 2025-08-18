//! Managing the process Routinator runs in.

use std::fs;
use std::future::Future;
use std::net::TcpListener;
use log::error;
use tokio::runtime::Runtime;
use crate::config::Config;
use crate::error::Failed;
use crate::log::{Logger, LogOutput};


//------------ Process -------------------------------------------------------

/// A representation of the process Routinator runs in.
///
/// This type provides access to the configuration and the environment in a
/// platform independent way.
pub struct Process {
    config: Config,
    service: Option<ServiceImpl>,
}

impl Process {
    pub fn init() -> Result<(), Failed> {
        Logger::init()?;

        Ok(())
    }

    /// Creates a new process object.
    ///
    pub fn new(config: Config) -> Self {
        Process { 
            service: Some(ServiceImpl::new(&config)),
            config
        }
    }

    /// Returns a reference to the config.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Returns an exclusive reference to the config.
    pub fn config_mut(&mut self) -> &mut Config {
        &mut self.config
    }
}

/// # Logging
///
impl Process {
    /// Switches logging to the configured target.
    ///
    /// Once the configuration has been successfully loaded, logging should
    /// be switched to whatever the user asked for via this method.
    pub fn switch_logging(
        &self,
        daemon: bool,
        with_output: bool
    ) -> Result<Option<LogOutput>, Failed> {
        Logger::switch_logging(&self.config, daemon, with_output)
    }

    /// Rotates the log file if necessary.
    pub fn rotate_log(&self) -> Result<(), Failed> {
        Logger::rotate_log()
    }
}


/// # System Service
///
impl Process {
    /// Sets up the system service.
    ///
    /// If `detach` is `true`, the service will detach from the current
    /// process and keep running in the background.
    ///
    /// After the method returns, we will be running in the final process
    /// but still have the same privileges as when we were initially started.
    /// Whether there is still a terminal and standard stream available
    /// depends on the config.
    ///
    /// This method may encounter and log errors after detaching. You should
    /// therefore call `switch_logging` before this method.
    pub fn setup_service(&mut self, detach: bool) -> Result<(), Failed> {
        self.service.as_mut().unwrap().setup_service(&self.config, detach)
    }

    /// Drops privileges.
    ///
    /// If requested via the config, this method will drop all potentially
    /// elevated privileges. This may include loosing root or system
    /// administrator permissions and change the file system root.
    pub fn drop_privileges(&mut self) -> Result<(), Failed> {
        self.service.take().unwrap().drop_privileges(&mut self.config)
    }

    /// Returns the first listen socket passed into the process if available.
    pub fn get_listen_fd(&self) -> Result<Option<TcpListener>, Failed> {
        if self.config.systemd_listen {
            match listenfd::ListenFd::from_env().take_tcp_listener(0) {
                Ok(Some(res)) => Ok(Some(res)),
                Ok(None) => {
                    error!(
                        "Fatal: systemd_listen enabled \
                         but no socket available."
                    );
                    Err(Failed)
                }
                Err(err) => {
                    error!(
                        "Fatal: failed to get systemd_listen socket:  {err}"
                    );
                    Err(Failed)
                }
            }
        }
        else {
            Ok(None)
        }
    }
}


/// # Directory Management
///
impl Process {
    /// Creates the cache directory.
    ///
    /// This will also change ownership of the directory if necessary.
    pub fn create_cache_dir(&self) -> Result<(), Failed> {
        if let Err(err) = fs::create_dir_all(&self.config.cache_dir) {
            error!("Fatal: failed to create cache directory {}: {}",
                self.config.cache_dir.display(), err
            );
            return Err(Failed)
        }
        ServiceImpl::prepare_cache_dir(&self.config)
    }
}


/// # Tokio Runtime
///
impl Process {
    /// Returns a Tokio runtime based on the configuration.
    pub fn runtime(&self) -> Result<Runtime, Failed> {
        Runtime::new().map_err(|err| {
            error!("Failed to create runtime: {err}");
            Failed
        })
    }

    /// Runs a future to completion atop a Tokio runtime.
    pub fn block_on<F: Future>(&self, future: F) -> Result<F::Output, Failed> {
        Ok(self.runtime()?.block_on(future))
    }
}


//------------ Platform-dependent Service Implementation ---------------------

#[cfg(unix)]
use self::unix::ServiceImpl;

#[cfg(not(unix))]
use self::noop::ServiceImpl;


/// Unix “Service.”
///
/// This implementation is based on the 
/// [daemonize](https://github.com/knsd/daemonize) crate.
///
#[cfg(unix)]
mod unix {
    use std::env::set_current_dir;
    use std::ffi::CString;
    use std::fs::{File, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;
    use log::error;
    use nix::libc;
    use nix::fcntl::{Flock, FlockArg};
    use nix::unistd::{chown, chroot, fork, getpid, setgid, setuid, Gid, Uid};
    use crate::config::Config;
    use crate::error::Failed;

    #[derive(Debug, Default)]
    pub struct ServiceImpl {
        pid_file: Option<Flock<File>>,
        uid: Option<Uid>,
        gid: Option<Gid>,
    }

    impl ServiceImpl {
        pub fn new(_config: &Config) -> Self {
            ServiceImpl::default()
        }

        pub fn setup_service(
            &mut self, config: &Config, detach: bool
        ) -> Result<(), Failed> {
            if let Some(pid_file) = config.pid_file.as_ref() {
                self.create_pid_file(pid_file)?
            }
            if detach {
                self.perform_fork()?
            }

            if let Some(path) = config.working_dir.as_ref().or(
                config.chroot.as_ref()
            ) {
                if let Err(err) = set_current_dir(path) {
                    error!("Fatal: failed to set working directory {}: {}",
                        path.display(), err
                    );
                    return Err(Failed)
                }
            }

            // set_sid 
            // umask
            if detach {
                self.perform_fork()?
            }
            // redirect_standard_streams
            self.uid = Self::get_user(config)?;
            self.gid = Self::get_group(config)?;
            // chown_pid_file
            
            Ok(())
        }

        pub fn drop_privileges(
            mut self, config: &mut Config
        ) -> Result<(), Failed> {
            config.adjust_chroot_paths()?;
            if let Some(path) = config.chroot.as_ref() {
                if let Err(err) = chroot(path) {
                    error!("Fatal: cannot chroot to '{}': {}'",
                        path.display(), err
                    );
                    return Err(Failed)
                }
            }
            if let Some(gid) = self.gid {
                if let Err(err) = setgid(gid) {
                    error!("Fatal: failed to set group: {err}");
                    return Err(Failed)
                }
            }
            if let Some(uid) = self.uid {
                if let Err(err) = setuid(uid) {
                    error!("Fatal: failed to set user: {err}");
                    return Err(Failed)
                }
            }
            self.write_pid_file()?;

            Ok(())
        }

        fn create_pid_file(&mut self, path: &Path) -> Result<(), Failed> {
            let file = OpenOptions::new()
                .read(false).write(true)
                .create(true).truncate(true)
                .mode(0o666)
                .open(path);
            let file = match file {
                Ok(file) => file,
                Err(err) => {
                    error!("Fatal: failed to create PID file {}: {}",
                        path.display(), err
                    );
                    return Err(Failed)
                }
            };
            let file = match Flock::lock(
                file, FlockArg::LockExclusiveNonblock
            ) {
                Ok(file) => file,
                Err((_, err)) => {
                    error!("Fatal: cannot lock PID file {}: {}",
                        path.display(), err
                    );
                    return Err(Failed)
                }
            };
            self.pid_file = Some(file);
            Ok(())
        }

        fn write_pid_file(&mut self) -> Result<(), Failed> {
            if let Some(pid_file) = self.pid_file.as_mut() {
                let pid = format!("{}", getpid());
                if let Err(err) = pid_file.write_all(pid.as_bytes()) {
                    error!(
                        "Fatal: failed to write PID to PID file: {err}"
                    );
                    return Err(Failed)
                }
            }
            Ok(())
        }

        fn perform_fork(&self) -> Result<(), Failed> {
            match unsafe { fork() } {
                Ok(res) => {
                    if res.is_parent() {
                        std::process::exit(0)
                    }
                    Ok(())
                }
                Err(err) => {
                    error!("Fatal: failed to detach: {err}");
                    Err(Failed)
                }
            }
        }

        fn get_user(config: &Config) -> Result<Option<Uid>, Failed> {
            let name = match config.user.as_ref() {
                Some(name) => name,
                None => return Ok(None)
            };
            let cname = match CString::new(name.clone()) {
                Ok(name) => name,
                Err(_) => {
                    error!("Fatal: invalid user ID '{name}'");
                    return Err(Failed)
                }
            };

            let uid = unsafe {
                let ptr = libc::getpwnam(cname.as_ptr() as *const libc::c_char);
                if ptr.is_null() {
                    None
                }
                else {
                    let s = &*ptr;
                    Some(s.pw_uid)
                }
            };
            match uid {
                Some(uid) => Ok(Some(Uid::from_raw(uid))),
                None => {
                    error!("Fatal: unknown user ID '{name}'");
                    Err(Failed)
                }
            }
        }

        fn get_group(config: &Config) -> Result<Option<Gid>, Failed> {
            let name = match config.group.as_ref() {
                Some(name) => name,
                None => return Ok(None)
            };
            let cname = match CString::new(name.clone()) {
                Ok(name) => name,
                Err(_) => {
                    error!("Fatal: invalid user ID '{name}'");
                    return Err(Failed)
                }
            };

            let gid = unsafe {
                let ptr = libc::getgrnam(cname.as_ptr() as *const libc::c_char);
                if ptr.is_null() {
                    None
                }
                else {
                    let s = &*ptr;
                    Some(s.gr_gid)
                }
            };
            match gid {
                Some(gid) => Ok(Some(Gid::from_raw(gid))),
                None => {
                    error!("Fatal: unknown group ID '{name}'");
                    Err(Failed)
                }
            }
        }
     
        pub fn prepare_cache_dir(config: &Config) -> Result<(), Failed> {
            let uid = Self::get_user(config)?;
            let gid = Self::get_group(config)?;
            if uid.is_some() || gid.is_some() {
                if let Err(err) = chown(&config.cache_dir, uid, gid) {
                    error!(
                        "Fatal: failed to change ownership of cache dir \
                         {}: {}",
                        config.cache_dir.display(),
                        err
                    );
                    return Err(Failed)
                }
            }
            Ok(())
        }
    }
}

#[cfg(not(unix))]
mod noop {
    use crate::error::Failed;
    use crate::config::Config;

    pub struct ServiceImpl;

    impl ServiceImpl {
        pub fn new(_config: &Config) -> Self {
            ServiceImpl
        }

        pub fn setup_service(
            &mut self, _config: &Config, _detach: bool
        ) -> Result<(), Failed> {
            Ok(())
        }

        pub fn drop_privileges(
            self, _config: &mut Config
        ) -> Result<(), Failed> {
            Ok(())
        }
 
        pub fn prepare_cache_dir(_config: &Config) -> Result<(), Failed> {
            Ok(())
        }
    }
}
