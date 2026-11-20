//! A byte-level Aho–Corasick automaton over a fixed set of patterns (KNSH-090).
//!
//! The redactor runs one of these over the raw bytes and one over the percent-decoded bytes. Matching is linear in
//! the input whatever the patterns are, so an agent cannot make redaction slow by printing near-misses of a secret.
//! The trie is stored flat (one edge list per node, sorted by byte) because secret encodings are long unique paths:
//! nearly every node has one child, and a dense 256-entry table per node would cost a kilobyte for each byte of each
//! secret. Only the root, which every mismatch returns to, has a dense table.

use std::collections::VecDeque;

/// Marks "no pattern" in [`Automaton::output`].
const NONE: u32 = u32::MAX;

/// The root node; a transition to it is "no prefix of any pattern".
pub(super) const ROOT: u32 = 0;

/// One distinct pattern: its length in bytes and the secret it was derived from.
#[derive(Clone, Copy, Debug)]
pub(super) struct Pattern {
    /// Length in bytes (in the automaton's view: raw or decoded).
    pub(super) len: u32,
    /// Index of the secret, into the redactor's name list.
    pub(super) secret: u32,
}

/// Collects patterns, then builds the [`Automaton`].
pub(super) struct Builder {
    children: Vec<Vec<(u8, u32)>>,
    depth: Vec<u32>,
    owner: Vec<u32>,
    terminal: Vec<u32>,
    patterns: Vec<Pattern>,
}

impl Builder {
    pub(super) fn new() -> Self {
        Self {
            children: vec![Vec::new()],
            depth: vec![0],
            owner: vec![NONE],
            terminal: vec![NONE],
            patterns: Vec::new(),
        }
    }

    /// Adds `bytes` as a pattern of secret `secret`. A pattern already present keeps its first secret, so the
    /// marker it produces does not depend on anything but insertion order. Empty patterns are ignored.
    pub(super) fn insert(&mut self, bytes: &[u8], secret: u32) {
        if bytes.is_empty() {
            return;
        }
        let mut node = ROOT;
        for &byte in bytes {
            let at = node as usize;
            node = if let Some(&(_, next)) = self.children[at].iter().find(|(b, _)| *b == byte) {
                next
            } else {
                // The caller bounds the total pattern length (MAX_REDACTION_BYTES), far below u32::MAX nodes.
                let next = u32::try_from(self.children.len()).unwrap_or(NONE - 1);
                self.children[at].push((byte, next));
                self.children.push(Vec::new());
                self.depth.push(self.depth[at] + 1);
                self.owner.push(secret);
                self.terminal.push(NONE);
                next
            };
        }
        let at = node as usize;
        if self.terminal[at] == NONE {
            self.terminal[at] = u32::try_from(self.patterns.len()).unwrap_or(NONE - 1);
            self.patterns.push(Pattern {
                len: self.depth[at],
                secret,
            });
        }
    }

    /// Computes failure links, outputs and live nodes, and flattens the trie.
    pub(super) fn build(mut self) -> Automaton {
        let nodes = self.children.len();
        for list in &mut self.children {
            list.sort_unstable_by_key(|&(byte, _)| byte);
        }
        let mut fail = vec![ROOT; nodes];
        let mut output = vec![NONE; nodes];
        let mut live = vec![ROOT; nodes];
        let mut queue: VecDeque<u32> = VecDeque::new();
        queue.push_back(ROOT);
        // Breadth first, so a node's failure target (always shallower) is complete before the node.
        while let Some(node) = queue.pop_front() {
            let at = node as usize;
            for index in 0..self.children[at].len() {
                let (byte, child) = self.children[at][index];
                let c = child as usize;
                fail[c] = if node == ROOT {
                    ROOT
                } else {
                    let mut f = fail[at];
                    loop {
                        if let Some(next) = find(&self.children[f as usize], byte) {
                            break next;
                        }
                        if f == ROOT {
                            break ROOT;
                        }
                        f = fail[f as usize];
                    }
                };
                let f = fail[c] as usize;
                output[c] = if self.terminal[c] == NONE {
                    output[f]
                } else {
                    self.terminal[c]
                };
                live[c] = if self.children[c].is_empty() { live[f] } else { child };
                queue.push_back(child);
            }
        }

        let mut root = Box::new([ROOT; 256]);
        for &(byte, child) in &self.children[0] {
            root[byte as usize] = child;
        }
        let edges: usize = self.children.iter().map(Vec::len).sum();
        let mut first_edge = Vec::with_capacity(nodes + 1);
        let mut edge_bytes = Vec::with_capacity(edges);
        let mut edge_targets = Vec::with_capacity(edges);
        for list in &self.children {
            first_edge.push(u32::try_from(edge_bytes.len()).unwrap_or(NONE));
            for &(byte, child) in list {
                edge_bytes.push(byte);
                edge_targets.push(child);
            }
        }
        first_edge.push(u32::try_from(edge_bytes.len()).unwrap_or(NONE));

        // The temporary trie is wiped by `Builder`'s `Drop`.
        Automaton {
            root,
            first_edge,
            edge_bytes,
            edge_targets,
            fail,
            depth: std::mem::take(&mut self.depth),
            output,
            live,
            owner: std::mem::take(&mut self.owner),
            patterns: std::mem::take(&mut self.patterns),
        }
    }
}

impl Drop for Builder {
    fn drop(&mut self) {
        // The temporary trie spells out every pattern, also when building stops half way (a refused secret).
        for list in &mut self.children {
            for edge in list.iter_mut() {
                edge.0 = 0;
            }
            std::hint::black_box(list);
        }
    }
}

fn find(list: &[(u8, u32)], byte: u8) -> Option<u32> {
    list.binary_search_by_key(&byte, |&(b, _)| b).ok().map(|i| list[i].1)
}

/// The built automaton. Its state is a node: the longest suffix of the input so far that is a prefix of a pattern.
///
/// # Invariants
///
/// - `fail[n]` is the node of the longest proper suffix of `n`'s string that is also a trie node.
/// - `output[n]` is the longest pattern that is a suffix of `n`'s string, or none.
/// - `live[n]` is the deepest node on `n`'s failure chain (itself included) that has a child: the longest suffix of
///   the input that a later byte could still extend into a match. A match ending later starts no earlier than that.
pub(super) struct Automaton {
    root: Box<[u32; 256]>,
    first_edge: Vec<u32>,
    edge_bytes: Vec<u8>,
    edge_targets: Vec<u32>,
    fail: Vec<u32>,
    depth: Vec<u32>,
    output: Vec<u32>,
    live: Vec<u32>,
    owner: Vec<u32>,
    patterns: Vec<Pattern>,
}

impl Automaton {
    /// Whether the automaton has no pattern at all (every input passes through).
    pub(super) fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// The state after reading `byte` in state `state`. Amortised O(1) per byte.
    #[inline]
    pub(super) fn step(&self, mut state: u32, byte: u8) -> u32 {
        loop {
            if state == ROOT {
                return self.root[byte as usize];
            }
            let at = state as usize;
            let (start, end) = (self.first_edge[at] as usize, self.first_edge[at + 1] as usize);
            let bytes = &self.edge_bytes[start..end];
            let found = if bytes.len() <= 8 {
                bytes.iter().position(|&b| b == byte)
            } else {
                bytes.binary_search(&byte).ok()
            };
            if let Some(i) = found {
                return self.edge_targets[start + i];
            }
            state = self.fail[at];
        }
    }

    /// The longest pattern that ends at the input read so far, in state `state`.
    #[inline]
    pub(super) fn output(&self, state: u32) -> Option<Pattern> {
        let id = self.output[state as usize];
        (id != NONE).then(|| self.patterns[id as usize])
    }

    /// How many trailing input bytes (in this automaton's view) could still begin a match, and the secret the
    /// longest such prefix belongs to.
    pub(super) fn live_prefix(&self, state: u32) -> (u32, u32) {
        let live = self.live[state as usize] as usize;
        (self.depth[live], self.owner[live])
    }

    /// The secret of a pattern whose first byte's high nibble is `nibble`, if any: a dangling `%H` at the end of a
    /// stream is then the start of a percent-encoded secret.
    pub(super) fn first_byte_with_high_nibble(&self, nibble: u8) -> Option<u32> {
        (0..16u8)
            .map(|low| self.root[usize::from(nibble << 4 | low)])
            .find(|&child| child != ROOT)
            .map(|child| self.owner[child as usize])
    }

    /// The length of the longest pattern.
    pub(super) fn longest(&self) -> u32 {
        self.patterns.iter().map(|p| p.len).max().unwrap_or(0)
    }
}

impl Drop for Automaton {
    fn drop(&mut self) {
        // The edge bytes spell out every secret encoding; the root table reveals first bytes. Best effort: safe Rust
        // has no volatile write, so `black_box` is what keeps the compiler from dropping the stores.
        self.edge_bytes.fill(0);
        self.root.fill(ROOT);
        std::hint::black_box(&mut self.edge_bytes);
        std::hint::black_box(&mut self.root);
    }
}
