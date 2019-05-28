//! Various useful things.

use futures::Async;
use futures::future::{Future, IntoFuture};

//------------ FinishAll ----------------------------------------------------

/// A future combinator that simply finishes all its futures.
#[derive(Debug)]
#[must_use = "futures do nothing unless polled"]
pub struct FinishAll<A: Future> {
    inner: Vec<Option<A>>
}

/// Creates a new future that simply runs all futures to completion.
///
/// This is similar to `select_all` except that it doesn’t collect the
/// results but simply regards them.
///
/// Also unlike `select_all`, this is happily running on an empty iterator.
pub fn finish_all<I>(iter: I) -> FinishAll<<I::Item as IntoFuture>::Future>
where I: IntoIterator, I::Item: IntoFuture {
    FinishAll {
        inner: iter.into_iter().map(|a| Some(a.into_future())).collect()
    }
}

impl<A: Future> Future for FinishAll<A> {
    type Item = ();
    type Error = ();

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        let running = self.inner.iter_mut().filter_map(|fut| {
            *fut = match fut {
                Some(ref mut fut) => {
                    if let Ok(Async::NotReady) = fut.poll() {
                        // Unfinished future. Keep it and return a marker.
                        return Some(())
                    }
                    // We are done, either successfully or with an error.
                    // Replace the future with None.
                    None
                }
                None => return None
            };
            None
        }).count(); // We use count here so it won’t short-circuit.
        if running > 0 {
            Ok(Async::NotReady)
        }
        else {
            Ok(Async::Ready(()))
        }
    }
}

