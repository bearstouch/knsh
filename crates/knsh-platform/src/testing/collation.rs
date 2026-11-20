//! A collation the test controls.

use std::sync::Mutex;

use crate::collation::{Collation, is_c_locale, tie_break};

/// Sorts by bytes in the C locale and, in the locales it is given, case-insensitively (ties by bytes), a stand-in
/// for a locale's tables; any other locale is missing. Records the locales asked for.
#[derive(Debug, Default)]
pub struct FakeCollation {
    locales: Vec<String>,
    asked: Mutex<Vec<String>>,
}

impl FakeCollation {
    /// A collation with no locale but C.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds `locale`, which sorts case-insensitively.
    #[must_use]
    pub fn with_locale(mut self, locale: impl Into<String>) -> Self {
        self.locales.push(locale.into());
        self
    }

    /// The locales sorted in so far, in order.
    #[must_use]
    pub fn asked(&self) -> Vec<String> {
        super::lock(&self.asked).clone()
    }
}

impl Collation for FakeCollation {
    fn sort(&self, locale: &str, items: &mut [String]) -> bool {
        super::lock(&self.asked).push(locale.to_owned());
        items.sort_unstable();
        if is_c_locale(locale) {
            return true;
        }
        if !self.locales.iter().any(|known| known == locale) {
            return false;
        }
        items.sort_by(|a, b| a.to_lowercase().cmp(&b.to_lowercase()).then_with(|| tie_break(a, b)));
        true
    }
}
