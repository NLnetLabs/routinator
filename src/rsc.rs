use std::sync::atomic::{AtomicBool, Ordering};
use rpki::uri;
use rpki::repository::rsc;
use rpki::repository::cert::ResourceCert;
use rpki::repository::error::ValidationError;
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
    matched: AtomicBool,
    crl_found: AtomicBool,
    crl_failure: AtomicBool,
    strict: bool,
}

impl ValidationReport {
    pub fn new(
        rsc: Rsc, config: &Config
    ) -> Result<Self, ValidationError> {
        rsc.signed().cert().inspect_detached_ee(config.strict)?;
        Ok(Self {
            rsc: rsc.clone(),
            matched: AtomicBool::new(false),
            crl_found: AtomicBool::new(false),
            crl_failure: AtomicBool::new(false),
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
        if self.matched.load(Ordering::Relaxed)
            && !self.crl_failure.load(Ordering::Relaxed) {
            Ok(self.rsc.content().clone())
        } else {
            Err(Failed)
        }
    }
}

impl ValidationReport {
    fn supply_tal(&self, _tal: &Tal) -> Result<bool, ValidationError> {
        if self.matched.load(Ordering::Relaxed) {
            return Ok(true);
        }

        return Ok(false);
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
                self.matched.store(true, Ordering::Relaxed);
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
}

impl<'s> ValidateCa<'s> {
    fn new(report: &'s ValidationReport) -> Self {
        ValidateCa {
            report
        }
    }

    fn supply_ca(&self, ca: &ResourceCert) -> Result<bool, ValidationError> {
        if self.report.matched.load(Ordering::Relaxed)
         && self.report.crl_found.load(Ordering::Relaxed) {
            return Ok(true);
        }

        let cert = self.report.rsc.signed().cert().clone();
        let strict = self.report.strict;

        if cert.authority_key_identifier().is_none() {
            return Ok(false);
        }

        cert.inspect_detached_ee(strict)?;
        ca.inspect_ca(strict)?;
        cert.verify_ee(ca, strict)?;

        self.report.matched.store(true, Ordering::Relaxed);
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
        if self.report.matched.load(Ordering::Relaxed)
         && self.report.crl_found.load(Ordering::Relaxed) {
            return Ok(None)
        }
        if let Ok(true) = self.supply_ca(cert.cert()) {
            self.report.matched.store(true, Ordering::Relaxed)
        }
        Ok(Some(Self { report: self.report }))
    }

    fn process_crl(
        &mut self, 
        _uri: &uri::Rsync, 
        cert: ResourceCert, 
        crl: rpki::repository::Crl,
    ) -> Result<(), Failed> {
        let crl_uri = self.report.rsc.signed().cert().crl_uri();
        if crl_uri.is_none() || cert.crl_uri().is_none() {
            return Ok(());
        }

        if crl_uri != cert.crl_uri() {
            return Ok(());
        }

        self.report.crl_found.store(true, Ordering::Relaxed);

        if crl.contains(self.report.rsc.signed().cert().serial_number()) {
            self.report.crl_failure.store(true, Ordering::Relaxed);
        }

        Ok(())
    
    }

    fn restart(&mut self) -> Result<(), Failed> {
        Ok(())
    }

    fn commit(self) {

    }
}