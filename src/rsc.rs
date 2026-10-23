use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering::Relaxed;
use rpki::uri;
use rpki::repository::cert::Cert;
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
    rsc: Rsc,
    strict: bool,
    result: OnceLock<ResourceSignedChecklist>,
    done: AtomicBool,
}

impl ValidationReport {
    pub fn new(
        rsc: Rsc, config: &Config
    ) -> Result<Self, ValidationError> {
        rsc.signed().cert().inspect_detached_ee(config.strict)?;
        Ok(Self {
            rsc,
            strict: config.strict,
            result: OnceLock::new(),
            done: AtomicBool::new(false),
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
        self.result.into_inner().ok_or(Failed)
    }

    pub fn is_done(&self) -> bool {
        self.done.load(Relaxed)
    }

    pub fn mark_done(&self) {
        self.done.store(true, Relaxed);
    }
}

impl<'s> ProcessRun for &'s ValidationReport {
    type PubPoint = ValidateCa<'s>;

    fn process_ta(
        &self, _tal: &Tal, _uri: &TalUri, _cert: &CaCert,
        _tal_index: usize
    ) -> Result<Option<Self::PubPoint>, Failed> {
        if self.is_done() {
            return Ok(None)
        }
        Ok(Some(ValidateCa::new(self)))
    }
}


//------------ ValidateCa ----------------------------------------------------

#[derive(Clone, Copy)]
pub struct ValidateCa<'s> {
    report: &'s ValidationReport,
}

impl<'s> ValidateCa<'s> {
    fn new(report: &'s ValidationReport) -> Self {
        ValidateCa {
            report
        }
    }
}

impl ProcessPubPoint for ValidateCa<'_> {
    fn want(&self, _uri: &uri::Rsync) -> Result<bool, Failed> {
        Ok(false)
    }

    fn process_detached<F>(
        &mut self,
        ca_cert: &CaCert,
        check_crl: F
    ) -> Result<(), Failed>
    where F: Fn(&Cert) -> Result<(), ValidationError> {
        // Early return if we are done.
        if self.report.is_done() {
            return Ok(())
        }

        // Return early if the CA is not the issuer.
        if !self.report.rsc.is_issuer(ca_cert.cert(), self.report.strict) {
            return Ok(())
        }

        // Process the RSC and remember the result.
        let rsc = self.report.rsc.clone();
        if let Ok((_, checklist)) = rsc.process(
            ca_cert.cert(), self.report.strict, check_crl
        ) {
            // It’s fine if the result is set already, then the RSC validated
            // twice.
            let _ = self.report.result.set(checklist);
            self.report.mark_done();
        }

        Ok(())
    }

    fn process_ca(
        &mut self, _uri: &uri::Rsync, _cert: &CaCert,
    ) -> Result<Option<Self>, Failed> {
        if self.report.is_done() {
            return Ok(None)
        }
        Ok(Some(*self))
    }

    fn restart(&mut self) -> Result<(), Failed> {
        Ok(())
    }

    fn commit(self) {
    }
}

