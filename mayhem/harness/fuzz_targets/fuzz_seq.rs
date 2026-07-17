// Mayhem integration: input-driven variant of fuzz/fuzz_targets/fuzz_seq.rs.
//
// Upstream draws the seq arguments from the OS-seeded `rand::rng()`, so whether an execution
// panics is not a function of the input and no crash can be replayed. Here the argument vector is
// decoded from the fuzz input bytes, with the same shape as upstream (1..=3 arguments; mostly
// integers and floats, occasionally free text) and the same uutils-vs-GNU `seq` comparison.
#![no_main]
use libfuzzer_sys::fuzz_target;
use uu_seq::uumain;

use std::ffi::OsString;

use uufuzz::CommandResult;
use uufuzz::{compare_result, generate_and_run_uumain, run_gnu_cmd};

static CMD_PATH: &str = "seq";

// Characters seq's number parser treats specially (signs, exponent, hex, inf/nan, separators).
const TEXT_ALPHABET: &[u8] = b"0123456789.-+eExXpPiInNfFaAbBcCdD_,:%";

// Skip sequences whose output would not fit a fuzz iteration (seq prints one line per element).
const MAX_ELEMENTS: f64 = 100_000.0;

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn u8(&mut self) -> u8 {
        let b = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos += 1;
        b
    }
    fn u16(&mut self) -> u16 {
        u16::from_le_bytes([self.u8(), self.u8()])
    }
    fn u32(&mut self) -> u32 {
        u32::from_le_bytes([self.u8(), self.u8(), self.u8(), self.u8()])
    }
}

fn decode_arg(r: &mut Reader) -> String {
    let kind = r.u8();
    if kind % 32 == 0 {
        let len = 1 + (r.u8() % 12) as usize;
        return (0..len)
            .map(|_| TEXT_ALPHABET[r.u8() as usize % TEXT_ALPHABET.len()] as char)
            .collect();
    }
    match kind % 4 {
        0 => (i32::from(r.u16() % 20001) - 10000).to_string(),
        1 => {
            let unit = f64::from(r.u32()) / f64::from(u32::MAX);
            (-100.0 + unit * 200.0).to_string()
        }
        2 => (i32::from(r.u8() % 100) - 100).to_string(),
        _ => (i32::from(r.u8() % 100) + 1).to_string(),
    }
}

fn too_long(args: &[String]) -> bool {
    let nums: Option<Vec<f64>> = args.iter().map(|a| a.parse::<f64>().ok()).collect();
    let Some(n) = nums else { return false };
    let (first, inc, last) = match n.as_slice() {
        [last] => (1.0, 1.0, *last),
        [first, last] => (*first, 1.0, *last),
        [first, inc, last] => (*first, *inc, *last),
        _ => return false,
    };
    inc != 0.0 && ((last - first) / inc).abs() > MAX_ELEMENTS
}

fuzz_target!(|data: &[u8]| {
    let mut r = Reader { data, pos: 0 };
    let arg_count = 1 + (r.u8() % 3) as usize;
    let words: Vec<String> = (0..arg_count).map(|_| decode_arg(&mut r)).collect();
    if too_long(&words) {
        return;
    }

    let mut args = vec![OsString::from("seq")];
    args.extend(words.iter().map(OsString::from));

    let rust_result = generate_and_run_uumain(&args, uumain, None);

    let gnu_result = match run_gnu_cmd(CMD_PATH, &args[1..], false, None) {
        Ok(result) => result,
        Err(error_result) => {
            eprintln!("Failed to run GNU command:");
            eprintln!("Stderr: {}", error_result.stderr);
            eprintln!("Exit Code: {}", error_result.exit_code);
            CommandResult {
                stdout: String::new(),
                stderr: error_result.stderr,
                exit_code: error_result.exit_code,
            }
        }
    };

    compare_result(
        "seq",
        &format!("{:?}", &args[1..]),
        None,
        &rust_result,
        &gnu_result,
        false,
    );
});
