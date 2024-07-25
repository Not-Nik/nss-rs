// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(
    dead_code,
    non_upper_case_globals,
    non_snake_case,
    clippy::cognitive_complexity,
    clippy::too_many_lines
)]

use crate::prtypes::{
    PRBool, PRInt16, PRInt32, PRInt64, PRIntn, PROffset32, PROffset64, PRSize, PRStatus, PRUint16,
    PRUint32, PRUint64, PRUint8, PRUintn,
};

include!(concat!(env!("OUT_DIR"), "/nspr_io.rs"));
