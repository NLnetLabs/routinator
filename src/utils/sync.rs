//! Utilities for concurrency.

use std::sync::{Mutex as StdMutex, RwLock as StdRwLock};


pub use std::sync::{MutexGuard, RwLockReadGuard, RwLockWriteGuard};


//------------ RwLock --------------------------------------------------------

/// A wrapper around a std read-write lock that panics if it is poisoned.
#[derive(Debug, Default)]
pub struct RwLock<T: ?Sized>(StdRwLock<T>);

impl<T> RwLock<T> {
    /// Creates a new read/write lock in unlocked state.
    pub fn new(t: T) -> Self {
        RwLock(StdRwLock::new(t))
    }
}

impl<T: ?Sized> RwLock<T> {
    /// Acquires the locks for shared read access.
    ///
    /// The calling thread will be blocked until there are no more writers
    /// holding the lock. Multiple readers may access the lock concurrently.
    ///
    /// # Panics
    ///
    /// The method panics if the lock is poisoned, i.e., if a writer panicked
    /// while holding the write lock. It may also panic if the current thread
    /// already holds the lock.
    pub fn read(&self) -> RwLockReadGuard<T> {
        self.0.read().expect("acquiring a poisoned rwlock")
    }

    /// Acquires the lock for exclusive write access.
    ///
    /// The calling thread will be blocked until there are no more read or
    /// write locks.
    ///
    /// # Panics
    ///
    /// The method panics if the lock is poisoned, i.e., if a writer panicked
    /// while holding the write lock. It may also panic if the current thread
    /// already holds the lock.
    pub fn write(&self) -> RwLockWriteGuard<T> {
        self.0.write().expect("acquiring a poisoned rwlock")
    }
}


//------------ Mutex ---------------------------------------------------------

/// A wrapper around a std read-write mutex that panics if it is poisoned.
#[derive(Debug, Default)]
pub struct Mutex<T: ?Sized>(StdMutex<T>);

impl<T> Mutex<T> {
    /// Creates a new mutex in unlocked state.
    pub fn new(t: T) -> Self {
        Mutex(StdMutex::new(t))
    }

    /// Consumes the mutex, returning the underlying data.
    ///
    /// # Panics
    ///
    /// The method panics if the lock is poisoned, i.e., if a panic occured
    /// while holding the lock.
    pub fn into_inner(self) -> T {
        self.0.into_inner().expect("acquiring a poisoned mutex")
    }
}

impl<T: ?Sized> Mutex<T> {
    /// Acquires the mutex.
    ///
    /// The current thread will be blocked until nobody else holds the mutex.
    ///
    /// # Panics
    ///
    /// The method panics if the lock is poisoned, i.e., if a panic occured
    /// while holding the lock. It may also panic if the current thread
    /// already holds the lock.
    pub fn lock(&self) -> MutexGuard<T> {
        self.0.lock().expect("acquiring a poisoned mutex")
    }
}

