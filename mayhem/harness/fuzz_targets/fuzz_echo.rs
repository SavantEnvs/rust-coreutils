// Mayhem integration: input-driven echo harness that can fail its standard output.
//
// Upstream's fuzz/fuzz_targets/fuzz_echo.rs draws its arguments from the OS-seeded `rand::rng()`
// and captures stdout in a pipe, so a crash is not a function of the input and an output error
// is never seen. Here the first input byte picks where stdout goes (bit 0 set: /dev/full, every
// write fails with ENOSPC; clear: /dev/null) and the rest, split on NUL bytes, is echo's argv.
// uutils echo must report a failed write as an error, never panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use uu_echo::uumain;

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStringExt;
use std::sync::OnceLock;

static SINKS: OnceLock<(File, File)> = OnceLock::new();

fn sinks() -> &'static (File, File) {
    SINKS.get_or_init(|| {
        let open = |p| OpenOptions::new().write(true).open(p).expect("open sink");
        (open("/dev/null"), open("/dev/full"))
    })
}

fuzz_target!(|data: &[u8]| {
    let (mode, rest) = match data.split_first() {
        Some((m, r)) => (*m, r),
        None => (0, data),
    };

    let mut args = vec![OsString::from("echo")];
    if !rest.is_empty() {
        args.extend(rest.split(|b| *b == 0).map(|a| OsString::from_vec(a.to_vec())));
    }

    let (null, full) = sinks();
    let sink = if mode & 1 == 1 { full } else { null };
    if unsafe { libc::dup2(sink.as_raw_fd(), libc::STDOUT_FILENO) } == -1 {
        return;
    }

    let _ = uumain(args.into_iter());
});
