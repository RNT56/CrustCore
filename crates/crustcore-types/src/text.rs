// SPDX-License-Identifier: Apache-2.0
//! Bounded text. Nothing unbounded ever enters model context (CLAUDE.md §6.5:
//! "bounded everything"). `BoundedText` is the type used for model-visible
//! summaries, labels, and notes.

/// Error returned when constructing a [`BoundedText`] that exceeds the cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedTextError {
    /// The cap that was exceeded, in bytes.
    pub max: usize,
    /// The actual length that was rejected, in bytes.
    pub actual: usize,
}

impl core::fmt::Display for BoundedTextError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "text of {} bytes exceeds bound of {} bytes",
            self.actual, self.max
        )
    }
}

impl std::error::Error for BoundedTextError {}

/// UTF-8 text with an enforced maximum byte length.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BoundedText {
    text: String,
}

impl BoundedText {
    /// Default cap for general bounded text (64 KiB). Specific call sites may
    /// use [`BoundedText::with_max`] for tighter bounds.
    pub const DEFAULT_MAX: usize = 64 * 1024;

    /// Constructs bounded text using [`BoundedText::DEFAULT_MAX`].
    ///
    /// # Errors
    /// Returns [`BoundedTextError`] if the input exceeds the cap.
    pub fn new(text: impl Into<String>) -> Result<Self, BoundedTextError> {
        Self::with_max(text, Self::DEFAULT_MAX)
    }

    /// Constructs bounded text with an explicit byte cap.
    ///
    /// # Errors
    /// Returns [`BoundedTextError`] if the input exceeds `max`.
    pub fn with_max(text: impl Into<String>, max: usize) -> Result<Self, BoundedTextError> {
        let text = text.into();
        if text.len() > max {
            return Err(BoundedTextError {
                max,
                actual: text.len(),
            });
        }
        Ok(Self { text })
    }

    /// Constructs bounded text by truncating on a char boundary to fit `max`.
    #[must_use]
    pub fn truncated(text: impl Into<String>, max: usize) -> Self {
        let mut text = text.into();
        if text.len() > max {
            let mut end = max;
            while end > 0 && !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
        }
        Self { text }
    }

    /// Returns the text as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns the length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.text.len()
    }

    /// Returns true if empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }
}

impl core::fmt::Display for BoundedText {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.text)
    }
}
