//! How many terminal columns a character takes (KNSH-107): 0 for combining marks and other zero-width characters,
//! 2 for East Asian wide and fullwidth characters and emoji, 1 otherwise, as the system's `wcwidth` that readline
//! asks. The tables are in-house (no Unicode crate, `CLAUDE.md` dependency policy) and cover the ranges `wcwidth`
//! reports on macOS for the scripts people type at a prompt; a character outside them counts as 1.
//!
//! Control characters are not handled here: the editor shows them as `^X` ([`super::render`]).

/// Ranges (inclusive) of characters that take no column: combining marks (`Mn`, `Me`), zero-width spaces and
/// joiners, bidirectional controls, variation selectors, emoji skin-tone modifiers and tags.
const ZERO_WIDTH: &[(u32, u32)] = &[
    (0x0300, 0x036F),
    (0x0483, 0x0489),
    (0x0591, 0x05BD),
    (0x05BF, 0x05BF),
    (0x05C1, 0x05C2),
    (0x05C4, 0x05C5),
    (0x05C7, 0x05C7),
    (0x0610, 0x061A),
    (0x064B, 0x065F),
    (0x0670, 0x0670),
    (0x06D6, 0x06DC),
    (0x06DF, 0x06E4),
    (0x06E7, 0x06E8),
    (0x06EA, 0x06ED),
    (0x0711, 0x0711),
    (0x0730, 0x074A),
    (0x07A6, 0x07B0),
    (0x0900, 0x0902),
    (0x093A, 0x093A),
    (0x093C, 0x093C),
    (0x0941, 0x0948),
    (0x094D, 0x094D),
    (0x0951, 0x0957),
    (0x0962, 0x0963),
    (0x0E31, 0x0E31),
    (0x0E34, 0x0E3A),
    (0x0E47, 0x0E4E),
    (0x1160, 0x11FF),
    (0x1AB0, 0x1AFF),
    (0x1DC0, 0x1DFF),
    (0x200B, 0x200F),
    (0x202A, 0x202E),
    (0x2060, 0x2064),
    (0x20D0, 0x20FF),
    (0x302A, 0x302D),
    (0x3099, 0x309A),
    (0xFE00, 0xFE0F),
    (0xFE20, 0xFE2F),
    (0xFEFF, 0xFEFF),
    (0x1F3FB, 0x1F3FF),
    (0xE0000, 0xE0FFF),
];

/// Ranges (inclusive) of characters that take two columns: East Asian wide (`W`) and fullwidth (`F`) characters,
/// and emoji shown with emoji presentation.
const WIDE: &[(u32, u32)] = &[
    (0x1100, 0x115F),
    (0x231A, 0x231B),
    (0x2329, 0x232A),
    (0x23E9, 0x23EC),
    (0x23F0, 0x23F0),
    (0x23F3, 0x23F3),
    (0x25FD, 0x25FE),
    (0x2614, 0x2615),
    (0x2648, 0x2653),
    (0x267F, 0x267F),
    (0x2693, 0x2693),
    (0x26A1, 0x26A1),
    (0x26AA, 0x26AB),
    (0x26BD, 0x26BE),
    (0x26C4, 0x26C5),
    (0x26CE, 0x26CE),
    (0x26D4, 0x26D4),
    (0x26EA, 0x26EA),
    (0x26F2, 0x26F3),
    (0x26F5, 0x26F5),
    (0x26FA, 0x26FA),
    (0x26FD, 0x26FD),
    (0x2705, 0x2705),
    (0x270A, 0x270B),
    (0x2728, 0x2728),
    (0x274C, 0x274C),
    (0x274E, 0x274E),
    (0x2753, 0x2755),
    (0x2757, 0x2757),
    (0x2795, 0x2797),
    (0x27B0, 0x27B0),
    (0x27BF, 0x27BF),
    (0x2B1B, 0x2B1C),
    (0x2B50, 0x2B50),
    (0x2B55, 0x2B55),
    (0x2E80, 0x303E),
    (0x3041, 0x3096),
    (0x309B, 0x33FF),
    (0x3400, 0x4DBF),
    (0x4E00, 0x9FFF),
    (0xA000, 0xA4CF),
    (0xA960, 0xA97F),
    (0xAC00, 0xD7A3),
    (0xF900, 0xFAFF),
    (0xFE10, 0xFE19),
    (0xFE30, 0xFE6F),
    (0xFF00, 0xFF60),
    (0xFFE0, 0xFFE6),
    (0x16FE0, 0x16FE4),
    (0x17000, 0x18AFF),
    (0x1B000, 0x1B2FF),
    (0x1F004, 0x1F004),
    (0x1F0CF, 0x1F0CF),
    (0x1F18E, 0x1F18E),
    (0x1F191, 0x1F19A),
    (0x1F200, 0x1F251),
    (0x1F300, 0x1F320),
    (0x1F32D, 0x1F335),
    (0x1F337, 0x1F37C),
    (0x1F37E, 0x1F393),
    (0x1F3A0, 0x1F3CA),
    (0x1F3CF, 0x1F3D3),
    (0x1F3E0, 0x1F3F0),
    (0x1F3F4, 0x1F3F4),
    (0x1F3F8, 0x1F3FA),
    (0x1F400, 0x1F43E),
    (0x1F440, 0x1F440),
    (0x1F442, 0x1F4FC),
    (0x1F4FF, 0x1F53D),
    (0x1F54B, 0x1F54E),
    (0x1F550, 0x1F567),
    (0x1F57A, 0x1F57A),
    (0x1F595, 0x1F596),
    (0x1F5A4, 0x1F5A4),
    (0x1F5FB, 0x1F64F),
    (0x1F680, 0x1F6C5),
    (0x1F6CC, 0x1F6CC),
    (0x1F6D0, 0x1F6D2),
    (0x1F6D5, 0x1F6D7),
    (0x1F6DC, 0x1F6DF),
    (0x1F6EB, 0x1F6EC),
    (0x1F6F4, 0x1F6FC),
    (0x1F7E0, 0x1F7EB),
    (0x1F7F0, 0x1F7F0),
    (0x1F90C, 0x1F93A),
    (0x1F93C, 0x1F945),
    (0x1F947, 0x1F9FF),
    (0x1FA70, 0x1FAFF),
    (0x20000, 0x2FFFD),
    (0x30000, 0x3FFFD),
];

/// Whether `code` lies in one of `ranges` (sorted, not overlapping).
fn within(ranges: &[(u32, u32)], code: u32) -> bool {
    ranges
        .binary_search_by(|&(start, end)| {
            if end < code {
                std::cmp::Ordering::Less
            } else if start > code {
                std::cmp::Ordering::Greater
            } else {
                std::cmp::Ordering::Equal
            }
        })
        .is_ok()
}

/// The columns `ch` takes on a terminal: 0, 1 or 2. Control characters count as 0 here.
#[must_use]
pub fn char_width(ch: char) -> usize {
    let code = u32::from(ch);
    if code < 0x20 || (0x7F..0xA0).contains(&code) {
        return 0;
    }
    if code < 0x300 {
        return 1;
    }
    if within(ZERO_WIDTH, code) {
        0
    } else if within(WIDE, code) {
        2
    } else {
        1
    }
}

/// Whether `ch` takes no column and joins the character before it (a combining mark, a joiner): the editor moves
/// the cursor over a character and the zero-width ones after it together, as readline does.
#[must_use]
pub fn is_zero_width(ch: char) -> bool {
    !ch.is_control() && char_width(ch) == 0
}

/// The columns `text` takes, control characters counted as 0.
#[must_use]
pub fn str_width(text: &str) -> usize {
    text.chars().map(char_width).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    // KNSH-107: the widths `wcwidth` gives for ASCII, accented, combining, CJK and emoji characters.
    #[test]
    fn characters_have_terminal_widths() {
        assert_eq!(char_width('a'), 1);
        assert_eq!(char_width('é'), 1);
        assert_eq!(char_width('\u{301}'), 0);
        assert_eq!(char_width('日'), 2);
        assert_eq!(char_width('한'), 2);
        assert_eq!(char_width('ｱ'), 1);
        assert_eq!(char_width('Ａ'), 2);
        assert_eq!(char_width('😀'), 2);
        assert_eq!(char_width('\u{200D}'), 0);
        assert_eq!(char_width('\t'), 0);
        assert!(is_zero_width('\u{301}') && !is_zero_width('\n'));
        assert_eq!(str_width("日本語 ok"), 9);
    }

    #[test]
    fn tables_are_sorted_and_disjoint() {
        for table in [ZERO_WIDTH, WIDE] {
            assert!(table.iter().all(|(start, end)| start <= end));
            assert!(table.windows(2).all(|pair| pair[0].1 < pair[1].0));
        }
    }
}
