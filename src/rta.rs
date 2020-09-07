use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use rpki::uri;
use rpki::cert::ResourceCert;
use rpki::rta::{ResourceTaggedAttestation, Rta, Validation};
use rpki::tal::{Tal, TalUri};
use rpki::x509::ValidationError;
use crate::config::Config;
use crate::operation::Error;
use crate::repository::{ProcessCa, ProcessRun, Repository};


//------------ ValidationReport ----------------------------------------------

/// The result of an RTA validation run.
#[derive(Debug)]
pub struct ValidationReport<'a> {
    validation: Mutex<Validation<'a>>,
    complete: AtomicBool,
}

impl<'a> ValidationReport<'a> {
    pub fn new(
        rta: &'a Rta, config: &Config
    ) -> Result<Self, ValidationError> {
        Validation::new(rta, config.strict).map(|validation| {
            ValidationReport {
                validation: Mutex::new(validation),
                complete: AtomicBool::new(false)
            }
        })
    }

    pub fn process<'s>(&'s self, repo: &mut Repository) -> Result<(), Error> {
        repo.process(self).map(|_| ())
    }

    pub fn finalize(self) -> Result<&'a ResourceTaggedAttestation, Error> {
        self.validation.into_inner().unwrap().finalize().map_err(|_| Error)
    }
}

impl<'a, 's> ProcessRun for &'s ValidationReport<'a> {
    type ProcessCa = ValidateCa<'a, 's>;

    fn process_ta(
        &self, tal: &Tal, _uri: &TalUri, _cert: &ResourceCert
    ) -> Result<Option<Self::ProcessCa>, Error> {
        let mut validation = self.validation.lock().unwrap();
        match validation.supply_tal(tal) {
            Ok(true) | Err(_) => {
                self.complete.store(true, Ordering::Relaxed);
                Ok(None)
            }
            Ok(false) => {
                Ok(Some(ValidateCa::new(self)))
            }
        }
    }
}


//------------ ValidateCa ----------------------------------------------------

pub struct ValidateCa<'a, 's> {
    report: &'s ValidationReport<'a>,
    certs: Vec<ResourceCert>,
}

impl<'a, 's> ValidateCa<'a, 's> {
    fn new(report: &'s ValidationReport<'a>) -> Self {
        ValidateCa {
            report,
            certs: Vec::new()
        }
    }
}

impl<'a, 's> ProcessCa for ValidateCa<'a, 's> {
    fn want(&self, uri: &uri::Rsync) -> Result<bool, Error> {
        Ok(uri.ends_with(".cer"))
    }

    fn process_ca(
        &mut self, _uri: &uri::Rsync, cert: &ResourceCert
    ) -> Result<Option<Self>, Error> {
        if self.report.complete.load(Ordering::Relaxed) {
            return Ok(None)
        }
        self.certs.push(cert.clone());
        Ok(Some(Self::new(self.report)))
    }

    fn commit(self) {
        let mut validation = self.report.validation.lock().unwrap();
        for cert in self.certs {
            match validation.supply_ca(&cert) {
                Ok(true) | Err(_) => {
                    self.report.complete.store(true, Ordering::Relaxed)
                }
                Ok(false) => { }
            }
        }
    }
}

