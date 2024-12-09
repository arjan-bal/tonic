use std::sync::Mutex;

use hdrhistogram::{errors::RecordError, Counter, Histogram};

#[derive(Debug)]
pub struct LockingHistogram<T: Counter> {
    histogram: Mutex<Histogram<T>>,
}

impl<T: Counter> LockingHistogram<T> {
    pub fn record(&mut self, value: u64) -> Result<(), RecordError> {
        self.histogram.lock().unwrap().record(value)
    }

    pub fn new(histogram: Histogram<T>) -> LockingHistogram<T> {
        LockingHistogram {
            histogram: Mutex::new(histogram),
        }
    }

    pub fn swap(&self, new: Histogram<T>) -> Histogram<T> {
        let mut lock = self.histogram.lock().unwrap();
        std::mem::replace(&mut *lock, new)
    }
}
