// Mayhem integration: input-driven variant of fuzz/fuzz_targets/fuzz_split.rs.
//
// Upstream draws both the split options and the input text from the OS-seeded `rand::rng()`, so
// whether an execution panics is not a function of the fuzz input and no crash can be replayed. It
// also feeds the GNU child through a stdin pipe it writes without handling EPIPE, so a GNU `split`
// that exits early (bad option) makes the harness itself panic with `Failed to write to stdin`.
// Here the option (at most one, as upstream) and the input text are decoded from the fuzz input
// bytes, with the same uutils-vs-GNU `split` comparison, and the GNU child reads its stdin from a
// file (no pipe, no race).
#![no_main]
use libfuzzer_sys::fuzz_target;
use uu_split::uumain;

use std::ffi::OsString;
use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::process::{Command, Stdio};
use std::sync::Once;

use uufuzz::{CommandResult, compare_result, generate_and_run_uumain};

const SUFFIX_ALPHABET: &[u8] = b"abcXYZ019._-";
const SEPARATORS: [&str; 5] = [",", ";", ":", " ", "\n"];

// Keeps the number of output files (and `--filter` shell spawns) per execution small.
const MAX_INPUT_BYTES: usize = 256;

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
    fn rest(&self) -> &[u8] {
        self.data.get(self.pos..).unwrap_or(&[])
    }
}

fn decode_option(r: &mut Reader, args: &mut Vec<OsString>) {
    let mut push = |s: String| args.push(OsString::from(s));
    match r.u8() % 12 {
        0 => {
            push("-a".into());
            push((1 + r.u8() % 8).to_string());
        }
        1 => {
            push("--additional-suffix".into());
            let len = 1 + (r.u8() % 5) as usize;
            let suffix: String = (0..len)
                .map(|_| SUFFIX_ALPHABET[r.u8() as usize % SUFFIX_ALPHABET.len()] as char)
                .collect();
            push(suffix);
        }
        2 => {
            push("-b".into());
            let unit = if r.u8() % 2 == 0 { "" } else { "K" };
            push(format!("{}{unit}", 1 + r.u16() % 1024));
        }
        3 => {
            push("-C".into());
            push((1 + r.u16() % 1024).to_string());
        }
        4 => push("-d".into()),
        5 => push("-x".into()),
        6 => {
            push("-l".into());
            push((1 + r.u16() % 1000).to_string());
        }
        7 => {
            push("--filter".into());
            push("cat > /dev/null".into());
        }
        8 => {
            push("-t".into());
            push(SEPARATORS[r.u8() as usize % SEPARATORS.len()].into());
        }
        9 => push("--verbose".into()),
        10 => {
            push("-n".into());
            push((1 + r.u8() % 16).to_string());
        }
        _ => {}
    }
}

// uutils and GNU both write their output files into the current directory; keep that out of the
// fuzzer's working directory.
fn enter_scratch_dir() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let dir = std::env::temp_dir().join(format!("fuzz_split_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        std::env::set_current_dir(&dir).expect("enter scratch dir");
    });
}

fn run_gnu_split(args: &[OsString], input: &str) -> CommandResult {
    let mut stdin_file = tempfile_in_scratch();
    stdin_file.write_all(input.as_bytes()).expect("write stdin file");
    stdin_file.seek(SeekFrom::Start(0)).expect("rewind stdin file");

    let output = Command::new("split")
        .args(args)
        .env("LC_ALL", "C")
        .stdin(Stdio::from(stdin_file))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output();
    match output {
        Ok(output) => CommandResult {
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr)
                .split_once(':')
                .map(|x| x.1)
                .unwrap_or("")
                .trim()
                .to_string(),
            exit_code: output.status.code().unwrap_or(-1),
        },
        Err(e) => {
            eprintln!("Failed to run GNU command: {e}");
            CommandResult {
                stdout: String::new(),
                stderr: e.to_string(),
                exit_code: -1,
            }
        }
    }
}

fn tempfile_in_scratch() -> File {
    let path = std::env::temp_dir().join(format!("fuzz_split_stdin_{}", std::process::id()));
    let file = File::options()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .expect("create stdin file");
    let _ = std::fs::remove_file(&path);
    file
}

fuzz_target!(|data: &[u8]| {
    enter_scratch_dir();

    let mut r = Reader { data, pos: 0 };
    let mut args = vec![OsString::from("split")];
    decode_option(&mut r, &mut args);

    let rest = r.rest();
    let input = String::from_utf8_lossy(&rest[..rest.len().min(MAX_INPUT_BYTES)]).into_owned();

    let rust_result = generate_and_run_uumain(&args, uumain, Some(&input));
    let gnu_result = run_gnu_split(&args[1..], &input);

    compare_result(
        "split",
        &format!("{:?}", &args[1..]),
        None,
        &rust_result,
        &gnu_result,
        false,
    );
});
