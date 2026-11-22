//! KNSH-107 integration test: PTY-driven sessions comparing what the screen shows with bash for a set of editing
//! scripts (NFR-COMPAT-02).
//!
//! Each shell runs under a pseudo-terminal (`/usr/bin/script -q /dev/null …`) with `PS1='$ '`, `TERM=xterm` and a
//! UTF-8 locale; the test types the same keys into both (pausing after each piece so the shell reads them as a person
//! types them), then renders everything each terminal received with a small VT100 emulator ([`Vt`]) and compares
//! the final screens line by line. Bash is macOS's `/bin/bash` (3.2, readline 5.2), whose editing keys are the ones
//! the native editor follows. `knsh` runs in native mode (`[shell] hosted = "native"` in a temporary `HOME`).
//!
//! Real IME input and keyboard layouts are manual checks (pending).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[cfg(target_os = "macos")]
mod macos {
    use std::io::{Read, Write};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::Duration;

    /// A terminal's cell grid, fed with what a shell wrote: printable characters (wide ones take two cells), CR,
    /// LF, BS, tabs, and the CSI sequences readline and the native editor use (cursor moves, erase in line and
    /// display, insert and delete characters, insert mode); OSC strings and other sequences are dropped. It never
    /// scrolls: rows are added below as needed, so the whole session stays visible.
    struct Vt {
        rows: Vec<Vec<char>>,
        row: usize,
        col: usize,
        columns: usize,
        /// The last column was written: the next character goes to the next row (xterm's deferred wrap).
        pending_wrap: bool,
        insert: bool,
    }

    /// Marks the cell after a wide character.
    const WIDE_TAIL: char = '\0';

    fn width(ch: char) -> usize {
        let code = u32::from(ch);
        if (0x300..0x370).contains(&code) {
            0
        } else if (0x1100..0x1160).contains(&code)
            || (0x2E80..0xA4D0).contains(&code)
            || (0xAC00..0xD7A4).contains(&code)
            || (0xF900..0xFB00).contains(&code)
            || (0xFF00..0xFF61).contains(&code)
            || (0x1F300..0x1FA00).contains(&code)
        {
            2
        } else {
            1
        }
    }

    impl Vt {
        fn new(columns: usize) -> Self {
            Self {
                rows: vec![Vec::new()],
                row: 0,
                col: 0,
                columns,
                pending_wrap: false,
                insert: false,
            }
        }

        fn line(&mut self) -> &mut Vec<char> {
            while self.rows.len() <= self.row {
                self.rows.push(Vec::new());
            }
            let columns = self.columns;
            let line = &mut self.rows[self.row];
            if line.len() < columns {
                line.resize(columns, ' ');
            }
            line
        }

        fn put(&mut self, ch: char) {
            let w = width(ch);
            if w == 0 {
                // A combining mark joins the cell before it: not kept, the same for both shells.
                return;
            }
            if self.pending_wrap || self.col + w > self.columns {
                self.row += 1;
                self.col = 0;
                self.pending_wrap = false;
            }
            let (col, insert, columns) = (self.col, self.insert, self.columns);
            let line = self.line();
            if insert {
                for _ in 0..w {
                    line.insert(col, ' ');
                }
                line.truncate(columns);
            }
            line[col] = ch;
            if w == 2 {
                line[col + 1] = WIDE_TAIL;
            }
            self.col += w;
            if self.col >= self.columns {
                self.col = self.columns - 1;
                self.pending_wrap = true;
            }
        }

        fn csi(&mut self, params: &str, last: char) {
            let private = params.starts_with('?');
            let numbers: Vec<usize> = params
                .trim_start_matches('?')
                .split(';')
                .map(|part| part.parse().unwrap_or(0))
                .collect();
            let n = numbers.first().copied().filter(|n| *n > 0).unwrap_or(1);
            let first = numbers.first().copied().unwrap_or(0);
            if last != 'm' && last != 'h' && last != 'l' {
                self.pending_wrap = false;
            }
            match last {
                'A' => self.row = self.row.saturating_sub(n),
                'B' => self.row += n,
                'C' => self.col = (self.col + n).min(self.columns - 1),
                'D' => self.col = self.col.saturating_sub(n),
                'G' => self.col = (n - 1).min(self.columns - 1),
                'H' => {
                    self.row = n - 1;
                    self.col = numbers.get(1).copied().filter(|n| *n > 0).unwrap_or(1) - 1;
                }
                'K' => {
                    let col = self.col;
                    let line = self.line();
                    let range = match first {
                        1 => 0..=col,
                        2 => 0..=line.len() - 1,
                        _ => col..=line.len() - 1,
                    };
                    for cell in &mut line[range] {
                        *cell = ' ';
                    }
                }
                'J' => {
                    if first == 2 {
                        self.rows = vec![Vec::new()];
                        self.row = 0;
                        self.col = 0;
                    } else {
                        let col = self.col;
                        let line = self.line();
                        for cell in &mut line[col..] {
                            *cell = ' ';
                        }
                        self.rows.truncate(self.row + 1);
                    }
                }
                'P' => {
                    let (col, columns) = (self.col, self.columns);
                    let line = self.line();
                    for _ in 0..n {
                        if col < line.len() {
                            line.remove(col);
                        }
                    }
                    line.resize(columns, ' ');
                }
                '@' => {
                    let (col, columns) = (self.col, self.columns);
                    let line = self.line();
                    for _ in 0..n {
                        line.insert(col, ' ');
                    }
                    line.truncate(columns);
                }
                'h' | 'l' if !private && first == 4 => self.insert = last == 'h',
                _ => {}
            }
        }

        fn feed(&mut self, text: &str) {
            let mut chars = text.chars().peekable();
            while let Some(ch) = chars.next() {
                match ch {
                    '\r' => {
                        self.col = 0;
                        self.pending_wrap = false;
                    }
                    '\n' => {
                        self.row += 1;
                        self.pending_wrap = false;
                    }
                    '\u{8}' => {
                        self.col = self.col.saturating_sub(1);
                        self.pending_wrap = false;
                    }
                    '\t' => self.col = ((self.col / 8 + 1) * 8).min(self.columns - 1),
                    '\u{7}' | '\0' => {}
                    '\u{1b}' => match chars.next() {
                        Some('[') => {
                            let mut params = String::new();
                            for next in chars.by_ref() {
                                if ('@'..='~').contains(&next) {
                                    self.csi(&params, next);
                                    break;
                                }
                                params.push(next);
                            }
                        }
                        Some(']') => {
                            // OSC: up to BEL or ESC \.
                            while let Some(next) = chars.next() {
                                if next == '\u{7}' {
                                    break;
                                }
                                if next == '\u{1b}' && chars.peek() == Some(&'\\') {
                                    chars.next();
                                    break;
                                }
                            }
                        }
                        _ => {}
                    },
                    _ if ch.is_control() => {}
                    _ => self.put(ch),
                }
            }
        }

        /// The screen as text: each row without trailing blanks, empty rows at the end dropped.
        fn lines(&self) -> Vec<String> {
            let mut lines: Vec<String> = self
                .rows
                .iter()
                .map(|row| {
                    row.iter()
                        .filter(|ch| **ch != WIDE_TAIL)
                        .collect::<String>()
                        .trim_end()
                        .to_owned()
                })
                .collect();
            while lines.last().is_some_and(String::is_empty) {
                lines.pop();
            }
            lines
        }
    }

    const PATH: &str = "/bin:/usr/bin";

    /// A typed piece and the pause after it.
    type Keys = &'static [(&'static str, u64)];

    /// The editing scripts, typed in one session per shell.
    const SESSION: Keys = &[
        ("", 900),
        // Movement and insertion.
        ("echo hello\x01\x06\x06\x06\x06\x06X\x05Y\r", 400),
        // Wide characters: the cursor steps over two columns per character.
        ("echo 日本語\x02\x02X\r", 400),
        // A combining mark moves with its base character.
        ("echo e\u{301}a\x02\x02X\r", 400),
        // Kills append, then yank.
        ("echo one two three\x17\x17four \x19\r", 400),
        // History recall and kill to the end.
        ("echo first\r", 300),
        ("\x10\x01\x1bf\x0b second\r", 400),
        // History expansion, shown before it runs.
        ("echo a b c\r", 300),
        ("echo !$ !^\r", 400),
        // Transpose and kill to the start.
        ("junk\x15echo ab\x14\r", 400),
        // A line longer than the terminal, edited at its start.
        (
            "echo xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\x01\x1bfY\r",
            500,
        ),
        // Incremental search.
        ("echo alpha\r", 300),
        ("echo beta\r", 300),
        ("\x12alp", 300),
        ("\r", 400),
        // Completion of a directory name.
        ("echo /usr/loc\t", 400),
        ("\r", 400),
        // Ctrl-C is left out: bash 3.2 erases the line and sets `$?` to 1, where bash 5.2 (and the native shell)
        // shows `^C` and sets 130; `interrupt_abandons_the_line` covers it.
        // vi mode basics.
        ("set -o vi\r", 300),
        ("echo hello world\x1b", 800),
        ("0wcwbye\x1b", 800),
        ("\r", 400),
        ("exit\r", 600),
    ];

    /// Runs `program args` under a pseudo-terminal with `env`, typing `keys`, and returns what the terminal showed.
    fn under_terminal(program: &Path, args: &[&str], env: &[(&str, &str)], keys: Keys) -> String {
        let mut child = Command::new("/usr/bin/script")
            .arg("-q")
            .arg("/dev/null")
            .arg(program)
            .args(args)
            .env_clear()
            .env("PATH", PATH)
            .env("TERM", "xterm")
            .env("LANG", "en_US.UTF-8")
            .env("LC_ALL", "en_US.UTF-8")
            .env("COLUMNS", "80")
            .env("LINES", "24")
            .env("HISTFILE", "")
            .envs(env.iter().copied())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        for (text, pause) in keys {
            input.write_all(text.as_bytes()).unwrap();
            input.flush().unwrap();
            std::thread::sleep(Duration::from_millis(*pause));
        }
        drop(input);
        let mut output = Vec::new();
        child.stdout.take().unwrap().read_to_end(&mut output).unwrap();
        child.wait().unwrap();
        String::from_utf8_lossy(&output).into_owned()
    }

    /// A temporary `HOME` choosing native mode, with a `.bashrc` setting the prompt.
    fn native_home() -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let home = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("knsh-native-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&home).unwrap();
        // The configuration file where `knsh` reads it, named only by `EnginePaths`.
        let config = knsh_platform::EnginePaths::for_home(&home).unwrap().config_file();
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        std::fs::write(&config, "[shell]\nhosted = \"native\"\n").unwrap();
        std::fs::write(home.join(".bashrc"), "PS1='$ '\nHISTFILE=\n").unwrap();
        home
    }

    /// The screen after the session, from the first prompt on (what each shell prints before it is not compared).
    fn screen(transcript: &str) -> Vec<String> {
        let mut vt = Vt::new(80);
        vt.feed(transcript);
        let lines = vt.lines();
        let first = lines.iter().position(|line| line.starts_with("$ ")).unwrap_or(0);
        // Messages start with the shell's own name.
        lines[first..]
            .iter()
            .map(|line| {
                ["bash: ", "knsh: "]
                    .iter()
                    .find_map(|name| line.strip_prefix(name))
                    .map_or_else(|| line.clone(), |rest| format!("SHELL: {rest}"))
            })
            .collect()
    }

    // KNSH-107 (NFR-COMPAT-02): the same keys leave the same screen as bash's readline.
    pub fn editing_matches_bash() {
        let bash = under_terminal(
            Path::new("/bin/bash"),
            &["--norc", "--noprofile", "-i"],
            &[
                ("PS1", "$ "),
                ("BASH_SILENCE_DEPRECATION_WARNING", "1"),
                ("HOME", "/tmp"),
            ],
            SESSION,
        );
        let home = native_home();
        let knsh = under_terminal(
            Path::new(env!("CARGO_BIN_EXE_knsh")),
            &[],
            &[("HOME", home.to_str().unwrap()), ("SHELL", "/bin/zsh")],
            SESSION,
        );
        std::fs::remove_dir_all(&home).unwrap();
        let (bash_screen, knsh_screen) = (screen(&bash), screen(&knsh));
        let differences: Vec<String> = (0..bash_screen.len().max(knsh_screen.len()))
            .filter_map(|row| {
                let (b, k) = (bash_screen.get(row), knsh_screen.get(row));
                (b != k).then(|| format!("row {row}:\n  bash: {b:?}\n  knsh: {k:?}"))
            })
            .collect();
        assert!(
            differences.is_empty(),
            "screens differ:\n{}\n\nbash screen:\n{}\n\nknsh screen:\n{}",
            differences.join("\n"),
            bash_screen.join("\n"),
            knsh_screen.join("\n")
        );
    }

    #[test]
    fn emulator_wraps_and_erases_like_a_terminal() {
        let mut vt = Vt::new(5);
        vt.feed("abcdefg\r\n日本語\x1b[A\r\x1b[Kx\x1b]133;A\x07");
        assert_eq!(vt.lines(), ["abcde", "fg", "x", "語"]);
    }
}

#[cfg(target_os = "macos")]
#[test]
fn editing_matches_bash() {
    macos::editing_matches_bash();
}
