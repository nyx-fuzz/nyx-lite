use thiserror::Error;
use vmm::vstate::memory::GuestAddress;

#[derive(Error, Debug)]
pub enum NyxError {
    #[error("Failed Memory Operation")]
    Memory(MemoryError),
    //#[error("the data for key `{0}` is not available")]
    //Redaction(String),
    //#[error("invalid header (expected {expected:?}, found {found:?})")]
    //InvalidHeader {
    //    expected: String,
    //    found: String,
    //},
    //#[error("unknown data store error")]
    //Unknown,
}

#[derive(Error, Debug, PartialEq, Eq)]
pub enum MemoryError {
    #[error("could not read from p:{:x}", (.0).0)]
    CantAccessPhysicalPage(GuestAddress),
    #[error("page at page_table p:{:x}:{} is not present", (.0).0 ,.1)]
    PageNotPresent(GuestAddress, u64),
    #[error("no page mapped at {0:x}")]
    PageNotMapped(u64)
}