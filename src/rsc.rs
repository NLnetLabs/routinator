use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use rpki::uri;
use rpki::repository::rsc;
use rpki::repository::cert::{Overclaim, ResourceCert};
use rpki::repository::error::{InspectionError, ValidationError, VerificationError};
use rpki::repository::rsc::{ResourceSignedChecklist, Rsc};
use rpki::repository::tal::{Tal, TalUri};
use crate::config::Config;
use crate::engine::{CaCert, ProcessPubPoint, ProcessRun, Engine};
use crate::error::{Failed, RunFailed};


//------------ ValidationReport ----------------------------------------------

/// The result of an RSC validation run.
#[derive(Debug)]
pub struct ValidationReport {
    rsc: rsc::Rsc,
    complete: AtomicBool,
    strict: bool,
}

impl ValidationReport {
    pub fn new(
        rsc: Rsc, config: &Config
    ) -> Result<Self, ValidationError> {
        Ok(Self {
            rsc: rsc,
            complete: AtomicBool::new(false),
            strict: config.strict
        })
    }

    pub fn process(
        &self,
        engine: &Engine,
    ) -> Result<(), RunFailed> {
        let mut run = engine.start(self, false)?;
        run.process()?;
        run.cleanup()?;
        Ok(())
    }

    pub fn finalize(self) -> Result<ResourceSignedChecklist, Failed> {
        if self.complete.load(Ordering::Relaxed) {
            return Ok(self.rsc.content().clone());
        } else {
            return Err(Failed);
        }
    }
}

impl ValidationReport {
    fn supply_tal(&self, tal: &Tal) -> Result<bool, ValidationError> {
        if self.complete.load(Ordering::Relaxed) {
            return Ok(true);
        }

        let cert = self.rsc.signed().cert();

        if cert.is_self_signed() {
            return Ok(false);
        }

        if cert.subject_public_key_info() != tal.key_info() {
            return Ok(false);
        }

        cert.inspect_ta(self.strict)?;
        cert.verify_ta_ref(self.strict)?;

        Ok(true)
    }
}

impl<'s> ProcessRun for &'s ValidationReport {
    type PubPoint = ValidateCa<'s>;

    fn process_ta(
        &self, tal: &Tal, _uri: &TalUri, _cert: &CaCert,
        _tal_index: usize
    ) -> Result<Option<Self::PubPoint>, Failed> {

        match self.supply_tal(tal) {
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

pub struct ValidateCa<'s> {
    report: &'s ValidationReport,
    certs: Vec<ResourceCert>,
}

impl<'a, 's> ValidateCa<'s> {
    fn new(report: &'s ValidationReport) -> Self {
        ValidateCa {
            report,
            certs: Vec::new()
        }
    }

    fn supply_ca(&self, ca: &ResourceCert) -> Result<bool, ValidationError> {
        if self.report.complete.load(Ordering::Relaxed) {
            return Ok(true);
        }

        let cert = self.report.rsc.signed().cert();
        let strict = self.report.strict;

        if cert.authority_key_identifier().is_none() {
            return Ok(false);
        }

        if cert.verify_issuer_claim(ca, strict).is_err()
            || cert.verify_signature(ca, strict).is_err() 
        {
            return Ok(false);
        }

        if cert.basic_ca().is_some() {
            cert.inspect_ca(strict)?;
        }
        else {
            cert.inspect_detached_ee(strict)?;
        }
        cert.validity().verify().map_err(|e| VerificationError::from(e))?;

        self.report.complete.store(true, Ordering::Relaxed);
        Ok(true)
    }
}

impl ProcessPubPoint for ValidateCa<'_> {
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
        for cert in self.certs.iter() {
            match self.supply_ca(cert) {
                Ok(true) | Err(_) => {
                    self.report.complete.store(true, Ordering::Relaxed)
                }
                Ok(false) => { }
            }
        }
    }
}