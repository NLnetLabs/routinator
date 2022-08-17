use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use rpki::uri;
use rpki::repository::rta;
use rpki::repository::cert::ResourceCert;
use rpki::repository::error::ValidationError;
use rpki::repository::rta::{ResourceTaggedAttestation, Rta};
use rpki::repository::tal::{Tal, TalUri};
use crate::config::Config;
use crate::engine::{CaCert, ProcessPubPoint, ProcessRun, Engine};
use crate::error::Failed;


//------------ ValidationReport ----------------------------------------------

/// The result of an RTA validation run.
#[derive(Debug)]
pub struct ValidationReport<'a> {
    validation: Mutex<rta::Validation<'a>>,
    complete: AtomicBool,
}

impl<'a> ValidationReport<'a> {
    pub fn new(
        rta: &'a Rta, config: &Config
    ) -> Result<Self, ValidationError> {
        rta::Validation::new(rta, config.strict).map(|validation| {
            ValidationReport {
                validation: Mutex::new(validation),
                complete: AtomicBool::new(false)
            }
        })
    }

    pub fn process(
        &self,
        engine: &Engine,
    ) -> Result<(), Failed> {
        let mut run = engine.start(self)?;
        run.process()?;
        run.cleanup()?;
        Ok(())
    }

    pub fn finalize(self) -> Result<&'a ResourceTaggedAttestation, Failed> {
        self.validation.into_inner().unwrap().finalize().map_err(|_| Failed)
    }
}

impl<'a, 's> ProcessRun for &'s ValidationReport<'a> {
    type PubPoint = ValidateCa<'a, 's>;

    fn process_ta(
        &self, tal: &Tal, _uri: &TalUri, _cert: &CaCert,
        _tal_index: usize
    ) -> Result<Option<Self::PubPoint>, Failed> {
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

impl<'a, 's> ProcessPubPoint for ValidateCa<'a, 's> {
    fn want(&self, uri: &uri::Rsync) -> Result<bool, Failed> {
        Ok(uri.ends_with(".cer"))
    }

    fn process_ca(
        &mut self, _uri: &uri::Rsync, cert: &CaCert,
    ) -> Result<Option<Self>, Failed> {
        if self.report.complete.load(Ordering::Relaxed) {
            return Ok(None)
        }
        self.certs.push(cert.cert().clone());
        Ok(Some(Self::new(self.report)))
    }

    fn restart(&mut self) -> Result<(), Failed> {
        self.certs.clear();
        Ok(())
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

