//! The interactive shell of native mode (KNSH-107; NFR-COMPAT-02, NFR-COMPAT-10, FR-SES-22): an in-house line
//! editor close to bash's readline, the history list and history expansion, prompt strings, programmable completion,
//! start-up files and OSC 133 marks. No readline or line-editing crate (`CLAUDE.md` dependency policy).
//!
//! - [`keys`] turns terminal bytes into keys; [`editor`] is the emacs and vi keymaps as a pure state machine;
//!   [`line`](mod@line) holds the text with a cursor that steps over whole cells; [`width`] says how many columns a character
//!   takes; [`render`] draws the prompt and line, wrapping as the terminal does.
//! - [`history`] is the list with `HISTSIZE`, `HISTFILESIZE`, `HISTCONTROL` and the file format; [`expansion`] is
//!   `!` history expansion.
//! - [`prompt`] decodes `PS1` and `PS2` escapes; the interpreter then expands the result
//!   ([`Interpreter::expand_prompt`](crate::Interpreter::expand_prompt)).
//! - [`complete`] is the model of `complete` and `compgen` and the pure parts of completion; the matches come from
//!   [`Interpreter::complete`](crate::Interpreter::complete).
//! - [`startup`] says which start-up files bash would read; [`marks`] is OSC 133.
//! - [`session`] is the loop that ties them together over a [`Terminal`].
//!
//! # Boundaries
//!
//! - Pure where it can be: the editor, renderer, history, expansion, prompt decoding and completion model take
//!   values and return values; only [`session`] talks to a terminal, through the [`Terminal`] trait, and only the
//!   interpreter touches the filesystem (through [`knsh_platform::Fs`]).
//! - Out of scope (KNSH-107): `.inputrc` and `bind`; `fc`; `history -n`; `HISTIGNORE` and `HISTTIMEFORMAT`;
//!   `complete -C`, `-G` and the user, group, host and service actions; `compopt`; IME and keyboard layouts are
//!   manual checks.

pub mod complete;
pub mod editor;
pub mod expansion;
pub mod history;
pub mod keys;
pub mod line;
pub mod marks;
pub mod prompt;
pub mod render;
pub mod session;
pub mod startup;
pub mod width;

pub use prompt::decode as decode_prompt;
pub use session::{DescriptorTerminal, HostInfo, LineObserver, Session, SessionOptions, Terminal};
