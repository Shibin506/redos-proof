//! redos-proof: finds regular expressions that can take exponential or polynomial time on a backtracking
//! engine, and proves it by building the input that makes them slow.

pub mod analysis;
pub mod ast;
pub mod charset;
pub mod matcher;
pub mod nfa;
pub mod parser;
pub mod prove;
pub mod scan;
pub mod source;
#[rustfmt::skip]
mod folds;
#[rustfmt::skip]
mod tables;

pub use ast::{Dialect, Node, Regex};
pub use parser::{Flags, ParseError, parse};
