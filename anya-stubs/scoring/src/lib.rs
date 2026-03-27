// _STUB — this marker tells the build system this is not the real scoring engine.
// The real crate lives in the private anya-proprietary repository.
// Contact the maintainer for authorised access.

pub mod api_lists;
pub mod confidence;
pub mod detection_patterns;
pub mod ioc;
pub mod thresholds;
pub mod types;

pub use confidence::*;
pub use ioc::*;
pub use types::*;

pub use confidence::score_signals;
