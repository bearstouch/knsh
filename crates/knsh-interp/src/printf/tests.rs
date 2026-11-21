//! `printf` engine tests against bash 5.2 on macOS (KNSH-102; NFR-COMPAT-02).

use super::*;

/// A host in the C locale, with `%(…)T` printing its format and time, and `%n` recorded.
#[derive(Default)]
struct TestHost {
    counts: Vec<(String, usize)>,
    multibyte: bool,
}

impl Host for TestHost {
    fn time(&mut self, format: &str, seconds: i64) -> Result<Vec<u8>, Refusal> {
        Ok(format!("<{format}@{seconds}>").into_bytes())
    }

    fn assign_count(&mut self, name: &str, count: usize) -> Result<(), CountError> {
        self.counts.push((name.to_owned(), count));
        Ok(())
    }

    fn multibyte(&self) -> bool {
        self.multibyte
    }

    fn plain_numbers(&self, _grouping: bool) -> bool {
        true
    }
}

fn run(format_text: &str, args: &[&str]) -> Output {
    let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
    format(format_text, &args, &mut TestHost::default()).unwrap()
}

fn text(format_text: &str, args: &[&str]) -> String {
    String::from_utf8(run(format_text, args).bytes).unwrap()
}

// KNSH-102 acceptance: the format is reused while arguments remain, missing ones are empty or zero, and a format
// without conversions is printed once.
#[test]
fn printf_reuses_format_for_extra_args() {
    assert_eq!(text("%s\n", &["a", "b", "c"]), "a\nb\nc\n");
    assert_eq!(text("%s %s\n", &["a", "b", "c"]), "a b\nc \n");
    assert_eq!(text("%d-%d,", &["1", "2", "3"]), "1-2,3-0,");
    assert_eq!(text("x\n", &["a", "b"]), "x\n");
    assert_eq!(text("%s|%*d|", &["a", "3", "7", "b"]), "a|  7|b|0|");
}

// KNSH-102: `%q` quotes as bash 5.2 does, so the result reads back as the same word.
#[test]
fn printf_q_quotes_for_reuse() {
    let cases = [
        ("a b", "a\\ b"),
        ("it's", "it\\'s"),
        ("$x", "\\$x"),
        ("#a", "\\#a"),
        ("a#", "a#"),
        ("a\tb", "$'a\\tb'"),
        ("", "''"),
        ("a,b", "a\\,b"),
        ("!", "\\!"),
        ("~x", "\\~x"),
        ("a=~b:~c", "a=\\~b:\\~c"),
        ("new\nline", "$'new\\nline'"),
        ("q'\x01", "$'q\\'\\001'"),
    ];
    for (input, quoted) in cases {
        assert_eq!(text("%q", &[input]), quoted, "{input:?}");
    }
    // In the C locale a non-ASCII character is not printable: octal escapes; in UTF-8 it is kept.
    assert_eq!(text("%q", &["é"]), "$'\\303\\251'");
    let mut host = TestHost {
        multibyte: true,
        ..TestHost::default()
    };
    let out = format("%q", &["é".to_owned()], &mut host).unwrap();
    assert_eq!(out.bytes, "é".as_bytes());
    // `%Q` cuts the argument before quoting; `%q` cuts the quoted text.
    assert_eq!(text("%.3Q|%.3q", &["a b c", "a b c"]), "a\\ b|a\\ ");
}

// KNSH-102: integer and floating conversions as the C library formats them on macOS.
#[test]
fn numbers_format_like_the_c_library() {
    assert_eq!(
        text(
            "%05.1f|%-8.3e|%+g|% d|%#o|%#x|%.0f|%.0f|%g|%g|%#g|%G",
            &[
                "3.14159",
                "1234.5",
                "2.5",
                "7",
                "8",
                "0",
                "0.5",
                "1.5",
                "1e-5",
                "123456789",
                "1",
                "1e100"
            ]
        ),
        "003.1|1.234e+03|+2.5| 7|010|0|0|2|1e-05|1.23457e+08|1.00000|1E+100"
    );
    assert_eq!(
        text("%a|%.2a|%A|%a|%a", &["3.5", "1.0", "255", "0.1", "0"]),
        "0x1.cp+1|0x1.00p+0|0X1.FEP+7|0x1.999999999999ap-4|0x0p+0"
    );
    assert_eq!(
        text("%f %e %g %F|%5f|%05f", &["inf", "-inf", "nan", "inf", "inf", "inf"]),
        "inf -inf nan INF|  inf|  inf"
    );
    assert_eq!(
        text("%05s|%5.2s|%-5d|%05d|%.3d|%+.0d|", &["ab", "abc", "3", "-3", "5", "0"]),
        "000ab|   ab|3    |-0003|005|+|"
    );
    assert_eq!(
        text("%x %u %o", &["-1", "-1", "-8"]),
        "ffffffffffffffff 18446744073709551615 1777777777777777777770"
    );
    assert_eq!(text("%d|%d|%d|%d", &["0x1f", "010", " 12", "-0x10"]), "31|8|12|-16");
    assert_eq!(text("%d %d %d", &["'a", "\"é", "'"]), "97 -61 0");
    assert_eq!(
        text(
            "%.3g|%.10g|%g|%g|%g",
            &["0.0001234", "1234567890123", "100000", "1000000", "0"]
        ),
        "0.000123|1.23456789e+12|100000|1e+06|0"
    );
    assert_eq!(
        text("%*d|%-*d|%.*f", &["5", "3", "4", "2", "2", "3.14159"]),
        "    3|2   |3.14"
    );
    assert_eq!(
        text("%e|%x", &["0", "0x7fffffffffffffff"]),
        "0.000000e+00|7fffffffffffffff"
    );
}

// KNSH-102: a bad number is reported and the value read up to there used, with status 1; out of range is a
// warning; a bad conversion character stops the output.
#[test]
fn number_errors_and_bad_conversions_are_bash_messages() {
    let out = run("%d\n", &["12abc"]);
    assert_eq!(out.bytes, b"12\n");
    assert_eq!(out.messages, ["12abc: invalid number"]);
    assert!(out.failed);
    let out = run("%d|%d|%d", &["0x", "09", ""]);
    assert_eq!(out.bytes, b"0|0|0");
    assert_eq!(out.messages, ["0x: invalid hex number", "09: invalid octal number"]);
    let out = run("%d", &["99999999999999999999"]);
    assert_eq!(out.bytes, b"9223372036854775807");
    assert_eq!(out.messages, ["warning: 99999999999999999999: Result too large"]);
    assert!(!out.failed);
    let out = run("%i|%5%|\n", &["3"]);
    assert_eq!(
        (out.bytes.as_slice(), out.messages.as_slice()),
        (&b"3|"[..], &["`%': invalid format character".to_owned()][..])
    );
    assert!(out.failed);
    let out = run("%z\\n", &[]);
    assert_eq!(out.messages, ["`\\': invalid format character"]);
    let out = run("abc%", &[]);
    assert_eq!(
        (out.bytes.as_slice(), out.messages.as_slice()),
        (&b"abc"[..], &["`%': missing format character".to_owned()][..])
    );
}

// KNSH-102: escapes in the format and in `%b`'s argument, `\c` stopping everything, `%c` and missing arguments.
#[test]
fn escapes_and_strings() {
    assert_eq!(text("\\101\\0102|\\q|\\\"|\\c|%%\\n", &[]), "A\u{8}2|\\q|\"|\\c|%\n");
    assert_eq!(text("%b|%b", &["\\101\\0102\\x41", "\\u00e9"]), "ABA|é");
    assert_eq!(
        text("%.3s|%-6b|%b|after", &["abcdef", "a\\tb", "x\\cy", "never"]),
        "abc|a\tb   |x"
    );
    assert_eq!(text("[%3c][%-3c][%c][%c]", &["", "", "", "xyz"]), "[   ][   ][][x]");
    assert_eq!(text("%s%d[%5s]", &[]), "0[     ]");
    let out = run("\\x", &[]);
    assert_eq!(
        (out.bytes.as_slice(), out.messages.as_slice()),
        (&b"\\x"[..], &["missing hex digit for \\x".to_owned()][..])
    );
    assert!(!out.failed);
}

// KNSH-102: `%(…)T` reads its argument (default and `-1`: now, `-2`: the shell's start) and pads like `%s`; `%n`
// stores the bytes written so far in this pass.
#[test]
fn time_and_count_conversions() {
    assert_eq!(text("%(%F)T|%10(x)T|%()T", &["5", "6"]), "<%F@5>|     <x@6>|<%X@-1>");
    // Bash prints the `%` alone and reads on after it, so `%F` inside is a conversion of its own.
    let out = run("%(%F)X", &[]);
    assert_eq!(out.bytes, b"%(0.000000)X");
    assert_eq!(out.messages, ["warning: `X': invalid time format specification"]);
    let mut host = TestHost::default();
    let args = ["n".to_owned(), "m".to_owned()];
    let out = format("ab%ncd%n", &args, &mut host).unwrap();
    assert_eq!(out.bytes, b"abcd");
    assert_eq!(host.counts, [("n".to_owned(), 2), ("m".to_owned(), 4)]);
}

// KNSH-102: a hostile width is refused, not allocated.
#[test]
fn huge_fields_are_refused() {
    let args: Vec<String> = Vec::new();
    assert!(matches!(
        format("%99999999999d", &args, &mut TestHost::default()),
        Err(Refusal::Limit(..))
    ));
    assert!(matches!(
        format("%*d", &["2000000".to_owned()], &mut TestHost::default()),
        Err(Refusal::Limit(..))
    ));
}
