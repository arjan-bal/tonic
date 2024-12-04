use crate::worker;

pub struct BenchmarkClient {}

impl BenchmarkClient {
    pub fn shutdown(&mut self) {}

    pub fn create_and_start() -> BenchmarkClient {
        todo!()
    }

    pub fn get_stats(&mut self, _reset: bool) -> worker::ClientStats {
        todo!()
    }
}
