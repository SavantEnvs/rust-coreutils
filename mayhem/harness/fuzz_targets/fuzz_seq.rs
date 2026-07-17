// Mayhem integration: input-driven variant of fuzz/fuzz_targets/fuzz_seq.rs.
//
// Upstream draws the seq arguments from the OS-seeded `rand::rng()`, so whether an execution
// panics is not a function of the input and no crash can be replayed. Here the argument vector is
// decoded from the fuzz input bytes, with the same shape as upstream (1..=3 arguments; mostly
// integers and floats, occasionally free text) and the same uutils-vs-GNU `seq` comparison.
//
// One difference from upstream: GNU `seq` does its arithmetic in x87 80-bit long double, while
// uutils uses exact BigDecimal. For non-integer decimal arguments the two therefore legitimately
// differ in the last printed digits (`seq -77 -59.631376704115276 -10000` ends ...135817 in GNU, ...816
// exactly; hex floats such as `seq -341 0x.f08 7` break rounding ties differently). Those inputs are compared with a numeric tolerance covering long-double rounding
// (same line count, same number of fractional digits, values within 1e-13 of the largest argument
// or one unit in the last printed digit, which decides exact rounding ties).
// Decimal exponents beyond long double's range (`seq 496 7e440000 0`, `seq 1E-90000 0`) are
// rejected or underflow to 0 in GNU, so those inputs are skipped. Integer and free-text arguments,
// exit codes, and any larger difference are still compared exactly.
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

fn parse_hex(body: &str) -> Option<f64> {
    let (mantissa, exp) = match body.split_once(['p', 'P']) {
        Some((m, e)) => (m, e.parse::<i32>().ok()?),
        None => (body, 0),
    };
    let (int, frac) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    if int.is_empty() && frac.is_empty() {
        return None;
    }
    let mut v = 0.0_f64;
    for c in int.chars() {
        v = v * 16.0 + f64::from(c.to_digit(16)?);
    }
    let mut unit = 1.0 / 16.0;
    for c in frac.chars() {
        v += f64::from(c.to_digit(16)?) * unit;
        unit /= 16.0;
    }
    Some(v * 2.0_f64.powi(exp))
}

// seq also accepts hex numbers (`0xbFb00b0` is ~200M elements), which `f64::parse` rejects.
fn parse_number(s: &str) -> Option<f64> {
    let (neg, body) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let v = match body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        Some(hex) => parse_hex(hex)?,
        None => body.parse::<f64>().ok()?,
    };
    Some(if neg { -v } else { v })
}

fn too_long(args: &[String]) -> bool {
    let nums: Option<Vec<f64>> = args.iter().map(|a| parse_number(a)).collect();
    let Some(n) = nums else { return false };
    let (first, inc, last) = match n.as_slice() {
        [last] => (1.0, 1.0, *last),
        [first, last] => (*first, 1.0, *last),
        [first, inc, last] => (*first, *inc, *last),
        _ => return false,
    };
    inc != 0.0 && ((last - first) / inc).abs() > MAX_ELEMENTS
}

fn is_plain_decimal(s: &str) -> bool {
    s.bytes().all(|b| b"0123456789.+-eE".contains(&b)) && s.parse::<f64>().is_ok()
}

fn is_hex(s: &str) -> bool {
    let body = s.strip_prefix(['+', '-']).unwrap_or(s);
    body.starts_with("0x") || body.starts_with("0X")
}

fn is_number(s: &str) -> bool {
    (is_plain_decimal(s) || is_hex(s)) && parse_number(s).is_some()
}

fn is_integer(s: &str) -> bool {
    let body = s.strip_prefix(['+', '-']).unwrap_or(s);
    match body.strip_prefix("0x").or_else(|| body.strip_prefix("0X")) {
        Some(hex) => !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit()),
        None => !body.is_empty() && body.bytes().all(|b| b.is_ascii_digit()),
    }
}

// GNU seq rejects (or rounds to 0) a decimal exponent outside x87 long double's range (~4932).
fn beyond_long_double_range(args: &[String]) -> bool {
    args.iter().filter(|a| is_plain_decimal(a)).any(|a| {
        a.split_once(['e', 'E'])
            .and_then(|(_, exp)| exp.parse::<i64>().ok())
            .is_some_and(|exp| exp.abs() > 4000)
    })
}

// Digits after the point, up to an exponent (`1.5e+06` has 1).
fn fraction_digits(s: &str) -> usize {
    s.split_once('.')
        .map_or(0, |(_, frac)| frac.bytes().take_while(u8::is_ascii_digit).count())
}

// True when `rust` and `gnu` differ only by what x87 long-double rounding explains.
fn agree_up_to_long_double(words: &[String], rust: &CommandResult, gnu: &CommandResult) -> bool {
    if rust.exit_code != gnu.exit_code {
        return false;
    }
    let nums: Vec<f64> = words.iter().filter_map(|w| parse_number(w)).collect();
    let Some(&bound) = nums.last() else { return false };
    let scale = nums.iter().fold(0.0_f64, |m, x| m.max(x.abs()));
    // Long-double rounding error, or one unit in the last printed digit (it decides exact ties).
    let close = |a: &str, b: &str| match (a.parse::<f64>(), b.parse::<f64>()) {
        (Ok(x), Ok(y)) => {
            let last_digit = 10.0_f64.powi(-(fraction_digits(a) as i32));
            (x - y).abs() <= (1e-13 * scale).max(1.01 * last_digit)
        }
        _ => false,
    };
    let lines = |r: &CommandResult| -> Vec<String> {
        r.stdout.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect()
    };
    let (r, g) = (lines(rust), lines(gnu));
    let (short, long) = if r.len() <= g.len() { (&r, &g) } else { (&g, &r) };
    if long.len() > short.len() + 1 {
        return false;
    }
    let same_prefix = short
        .iter()
        .zip(long.iter())
        .all(|(a, b)| fraction_digits(a) == fraction_digits(b) && close(a, b));
    // At the end bound the long-double comparison may include or drop one element.
    let extra_ok = long.len() == short.len() || close(&long[short.len()], &bound.to_string());
    same_prefix && extra_ok
}

fuzz_target!(|data: &[u8]| {
    let mut r = Reader { data, pos: 0 };
    let arg_count = 1 + (r.u8() % 3) as usize;
    let words: Vec<String> = (0..arg_count).map(|_| decode_arg(&mut r)).collect();
    if too_long(&words) || beyond_long_double_range(&words) {
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

    let float_args = words.iter().all(|w| is_number(w)) && !words.iter().all(|w| is_integer(w));
    if float_args && agree_up_to_long_double(&words, &rust_result, &gnu_result) {
        return;
    }

    compare_result(
        "seq",
        &format!("{:?}", &args[1..]),
        None,
        &rust_result,
        &gnu_result,
        false,
    );
});
