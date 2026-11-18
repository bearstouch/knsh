//! Percentiles and summaries of measured samples (KNSH-076). Pure, so the arithmetic every verdict rests on is tested
//! on fixed samples.
//!
//! Percentiles are **nearest rank**: the p-th percentile of `n` samples is the smallest sample with at least p% of
//! the samples at or below it, the sample of rank `ceil(p * n / 100)`. It is always a value that was measured, never
//! an interpolation, so a reported p95 is a run that really took that long. The start-up benchmark (KNSH-024)
//! computes its percentiles the same way.

/// The nearest-rank `percent` percentile of `sorted` (ascending, non-empty; `percent` from 0 to 100).
pub(crate) fn percentile(sorted: &[f64], percent: usize) -> f64 {
    // ceil(percent * n / 100), at least 1: the 1-based rank of the sample. `clamp` keeps a percent over 100 in range.
    let rank = (percent * sorted.len()).div_ceil(100).clamp(1, sorted.len());
    sorted[rank - 1]
}

/// Summary of one series of samples, in the series' unit.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Summary {
    /// How many samples.
    pub(crate) count: usize,
    /// The smallest.
    pub(crate) min: f64,
    /// The median.
    pub(crate) p50: f64,
    /// The 95th percentile: the figure the phase 2 targets bound.
    pub(crate) p95: f64,
    /// The 99th percentile.
    pub(crate) p99: f64,
    /// The largest.
    pub(crate) max: f64,
}

impl Summary {
    /// Summarises `samples`; `None` when there are none, or when one is not a number (a sample that cannot be
    /// ordered would make every percentile meaningless).
    pub(crate) fn of(samples: &[f64]) -> Option<Self> {
        if samples.iter().any(|sample| sample.is_nan()) {
            return None;
        }
        let mut sorted = samples.to_vec();
        sorted.sort_by(f64::total_cmp);
        Some(Self {
            count: sorted.len(),
            min: *sorted.first()?,
            p50: percentile(&sorted, 50),
            p95: percentile(&sorted, 95),
            p99: percentile(&sorted, 99),
            max: *sorted.last()?,
        })
    }
}

/// A duration in milliseconds.
pub(crate) fn ms(duration: std::time::Duration) -> f64 {
    duration.as_secs_f64() * 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    // KNSH-076: the harness computes percentiles correctly on fixed samples. Nearest rank over 1..=20: p95 is the
    // 19th sample, not the maximum and not an interpolation between the 19th and the 20th.
    #[test]
    fn benchmark_harness_reports_p95() {
        // Shuffled on purpose: the summary sorts.
        let samples: Vec<f64> = [7, 3, 20, 1, 15, 9, 12, 2, 18, 5, 11, 4, 16, 8, 19, 6, 14, 10, 17, 13]
            .iter()
            .map(|&n| f64::from(n))
            .collect();
        let summary = Summary::of(&samples).unwrap();
        assert_eq!(summary.count, 20);
        assert_eq!(summary.min, 1.0);
        assert_eq!(summary.p50, 10.0);
        assert_eq!(summary.p95, 19.0);
        assert_eq!(summary.p99, 20.0);
        assert_eq!(summary.max, 20.0);

        // 100 samples 1..=100: p95 is exactly the 95th; one slow outlier moves the max, never the p95.
        let mut hundred: Vec<f64> = (1..=100).map(f64::from).collect();
        assert_eq!(Summary::of(&hundred).unwrap().p95, 95.0);
        hundred[99] = 10_000.0;
        let summary = Summary::of(&hundred).unwrap();
        assert_eq!((summary.p95, summary.max), (95.0, 10_000.0));
    }

    #[test]
    fn percentile_edges() {
        assert_eq!(percentile(&[4.5], 95), 4.5, "one sample is every percentile");
        assert_eq!(percentile(&[1.0, 2.0], 0), 1.0);
        assert_eq!(percentile(&[1.0, 2.0], 100), 2.0);
        assert_eq!(percentile(&[1.0, 2.0], 50), 1.0, "rank ceil(1.0) = 1");
        assert_eq!(
            percentile(&[1.0, 2.0, 3.0], 150),
            3.0,
            "out-of-range percent stays in range"
        );
    }

    // A series with nothing in it, or with a value that cannot be ordered, has no summary rather than a made-up one.
    #[test]
    fn no_summary_without_orderable_samples() {
        assert_eq!(Summary::of(&[]), None);
        assert_eq!(Summary::of(&[1.0, f64::NAN]), None);
    }

    #[test]
    fn milliseconds_keep_fractions() {
        assert_eq!(ms(std::time::Duration::from_micros(1_500)), 1.5);
    }
}
