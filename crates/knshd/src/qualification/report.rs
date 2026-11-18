//! What a qualification run measured, and the reports written from it (KNSH-076).
//!
//! A [`Measurement`] holds the raw series it measured, the figure compared with its target, and its [`Outcome`]. The
//! outcome is derived, never typed in: [`Measurement::judge`] compares the figure with the bound, and anything that
//! could not be measured is [`Outcome::NotMeasured`] with its reason. A miss is reported with the figure as measured
//! and listed as an open item; nothing is rounded towards the target (the figures are printed with two decimals, and
//! the comparison uses the unrounded value).

use std::fmt::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use super::stats::Summary;

/// Overrides where the reports are written (default `target/qualification`).
const DIR_VAR: &str = "KNSH_QUALIFICATION_DIR";

/// The unit of a series and of a figure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unit {
    /// Milliseconds.
    Ms,
    /// Megabytes (10^6 bytes): the stricter reading of "50 MB".
    Mb,
}

impl Unit {
    /// The unit as written after a figure.
    pub(crate) const fn symbol(self) -> &'static str {
        match self {
            Self::Ms => "ms",
            Self::Mb => "MB",
        }
    }
}

/// One named series of raw samples.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Series {
    /// What was sampled, for the report and the samples file (no commas).
    pub(crate) name: String,
    /// The samples, in the order they were taken.
    pub(crate) values: Vec<f64>,
}

impl Series {
    /// A series named `name`.
    pub(crate) fn new(name: &str, values: Vec<f64>) -> Self {
        Self {
            name: name.replace(',', ";"),
            values,
        }
    }
}

/// How a measurement compares with its target.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Outcome {
    /// The figure is under the bound.
    Met,
    /// The figure is not under the bound, or a check of the measurement failed: why, with the figure as measured.
    Missed(String),
    /// Nothing could be measured: why.
    NotMeasured(String),
}

/// One target of `specs/07-testing/performance-validation.md`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Target {
    /// The requirement, `NFR-PERF-01`.
    pub(crate) requirement: &'static str,
    /// The target as the specification writes it.
    pub(crate) text: &'static str,
    /// The unit of the series, the figure and the bound.
    pub(crate) unit: Unit,
    /// The figure must be strictly under this. `None` for a target that is a property rather than a number (hook
    /// time is reported and bounded by its own timeout): only its checks decide it.
    pub(crate) bound: Option<f64>,
}

/// What was measured for one [`Target`].
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Measurement {
    /// The target measured.
    pub(crate) target: Target,
    /// What the figure is (`p95 of supervised − p95 of plain`), for the summary table.
    pub(crate) figure_label: String,
    /// The figure compared with the bound; `None` when nothing was measured.
    pub(crate) figure: Option<f64>,
    /// How it was measured.
    pub(crate) method: String,
    /// The raw samples.
    pub(crate) series: Vec<Series>,
    /// Facts the reader needs next to the numbers (exclusions, limits of the method).
    pub(crate) notes: Vec<String>,
    /// Checks of the measurement itself that failed (a line that did not run, a hook over its timeout): each makes
    /// the outcome a miss whatever the figure.
    pub(crate) failed_checks: Vec<String>,
    /// The verdict, set by [`Measurement::judge`].
    pub(crate) outcome: Outcome,
}

impl Measurement {
    /// A measurement of `target` with nothing measured yet.
    pub(crate) fn new(target: Target) -> Self {
        Self {
            target,
            figure_label: String::new(),
            figure: None,
            method: String::new(),
            series: Vec::new(),
            notes: Vec::new(),
            failed_checks: Vec::new(),
            outcome: Outcome::NotMeasured("not run".to_owned()),
        }
    }

    /// A measurement of `target` that could not be taken, for `reason`.
    pub(crate) fn not_measured(target: Target, reason: &str) -> Self {
        Self {
            outcome: Outcome::NotMeasured(reason.to_owned()),
            ..Self::new(target)
        }
    }

    /// Sets the outcome from the figure, the bound and the checks. Without a figure the target is not measured.
    #[must_use]
    pub(crate) fn judge(mut self) -> Self {
        let unit = self.target.unit.symbol();
        self.outcome = match (self.figure, self.target.bound) {
            // A check that failed means the run did not measure what it claims: a miss, with or without a figure.
            _ if !self.failed_checks.is_empty() => Outcome::Missed(self.failed_checks.join("; ")),
            (None, _) => Outcome::NotMeasured("no samples".to_owned()),
            // Strictly under: every target is written "under".
            (Some(figure), Some(bound)) if figure >= bound => Outcome::Missed(format!(
                "{} is {figure:.2} {unit}, not under {bound} {unit}",
                self.figure_label
            )),
            (Some(_), _) => Outcome::Met,
        };
        self
    }
}

/// The machine a run measured, as the report records it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct Machine {
    /// `hw.model`, `MacBookPro18,3`.
    pub(crate) model: String,
    /// `machdep.cpu.brand_string`, `Apple M1 Pro`.
    pub(crate) cpu: String,
    /// `uname -m`.
    pub(crate) arch: String,
    /// Logical CPUs.
    pub(crate) cpus: String,
    /// Memory in GiB.
    pub(crate) memory_gib: String,
    /// `sw_vers`: version and build.
    pub(crate) macos: String,
    /// The commit measured, `-dirty` when the tree had changes.
    pub(crate) commit: String,
    /// `release` or `debug`: the profile this test binary, and the binaries beside it, were built with.
    pub(crate) build: String,
    /// When the run ended, UTC.
    pub(crate) date: String,
}

impl Machine {
    /// Whether this is an Apple silicon Mac, the machine the targets are validated on.
    pub(crate) fn is_apple_silicon(&self) -> bool {
        self.arch == "arm64" && self.cpu.starts_with("Apple ")
    }

    /// Describes this machine. Probes that fail read `unknown`.
    pub(crate) fn describe() -> Self {
        let memory_gib = probe("/usr/sbin/sysctl", &["-n", "hw.memsize"])
            .parse::<u64>()
            .map_or_else(|_| "unknown".to_owned(), |bytes| (bytes >> 30).to_string());
        let mut commit = probe("/usr/bin/git", &["rev-parse", "--short", "HEAD"]);
        // A measurement of uncommitted code says so.
        if probe("/usr/bin/git", &["status", "--porcelain"]) != "unknown" {
            commit.push_str("-dirty");
        }
        Self {
            model: probe("/usr/sbin/sysctl", &["-n", "hw.model"]),
            cpu: probe("/usr/sbin/sysctl", &["-n", "machdep.cpu.brand_string"]),
            arch: probe("/usr/bin/uname", &["-m"]),
            cpus: probe("/usr/sbin/sysctl", &["-n", "hw.ncpu"]),
            memory_gib,
            macos: macos_version(),
            commit,
            build: if cfg!(debug_assertions) { "debug" } else { "release" }.to_owned(),
            date: probe("/bin/date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"]),
        }
    }
}

/// `sw_vers`: `26.6.2 (25G83)`.
pub(crate) fn macos_version() -> String {
    format!(
        "{} ({})",
        probe("/usr/bin/sw_vers", &["-productVersion"]),
        probe("/usr/bin/sw_vers", &["-buildVersion"])
    )
}

/// The trimmed standard output of `program args` when it succeeds with some output, or `unknown`. Only for
/// describing the machine and tools.
pub(crate) fn probe(program: &str, args: &[&str]) -> String {
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

/// The open items a run leaves: each miss, each target not measured, and a machine that does not qualify.
pub(crate) fn open_items(machine: &Machine, measurements: &[Measurement]) -> Vec<String> {
    let mut items = Vec::new();
    if !machine.is_apple_silicon() {
        items.push("not run on an Apple silicon Mac: these figures do not qualify the phase 2 targets".to_owned());
    }
    if machine.build != "release" {
        items.push("not a release build: the figures do not represent what ships".to_owned());
    }
    for measurement in measurements {
        match &measurement.outcome {
            Outcome::Met => {}
            Outcome::Missed(why) => items.push(format!("{} missed: {why}", measurement.target.requirement)),
            Outcome::NotMeasured(why) => items.push(format!("{} not measured: {why}", measurement.target.requirement)),
        }
    }
    items
}

/// Renders the performance report. Pure, so its wording is tested.
pub(crate) fn render(machine: &Machine, measurements: &[Measurement]) -> String {
    let mut r = String::new();
    // `write!` to a String cannot fail.
    let _ = writeln!(r, "# Phase 2 performance qualification (KNSH-076)\n");
    let _ = writeln!(
        r,
        "Targets: `specs/04-non-functional-requirements/performance.md`. Method: \
         `specs/07-testing/performance-validation.md`. Raw samples: `performance-samples.csv` beside this report.\n"
    );
    let _ = writeln!(r, "## Machine\n\n| Field | Value |\n| --- | --- |");
    for (field, value) in [
        ("Model", &machine.model),
        ("CPU", &machine.cpu),
        ("Architecture", &machine.arch),
        ("Logical CPUs", &machine.cpus),
        ("Memory (GiB)", &machine.memory_gib),
        ("macOS", &machine.macos),
        ("Commit", &machine.commit),
        ("Build", &machine.build),
        ("Date", &machine.date),
    ] {
        let _ = writeln!(r, "| {field} | {value} |");
    }
    let _ = writeln!(
        r,
        "\n## Summary\n\n| Requirement | Target | Figure | Measured | Result |\n| --- | --- | --- | --- | --- |"
    );
    for m in measurements {
        let measured = m.figure.map_or_else(
            || "—".to_owned(),
            |figure| format!("{figure:.2} {}", m.target.unit.symbol()),
        );
        let result = match &m.outcome {
            Outcome::Met => "met",
            Outcome::Missed(_) => "**missed**",
            Outcome::NotMeasured(_) => "**not measured**",
        };
        let _ = writeln!(
            r,
            "| {} | {} | {} | {measured} | {result} |",
            m.target.requirement, m.target.text, m.figure_label
        );
    }
    for m in measurements {
        let _ = writeln!(r, "\n## {} — {}\n", m.target.requirement, m.target.text);
        if !m.method.is_empty() {
            let _ = writeln!(r, "{}\n", m.method);
        }
        let with_samples: Vec<(&Series, Summary)> = m
            .series
            .iter()
            .filter_map(|series| Some((series, Summary::of(&series.values)?)))
            .collect();
        if !with_samples.is_empty() {
            let unit = m.target.unit.symbol();
            let _ = writeln!(
                r,
                "| Series | n | min ({unit}) | p50 | p95 | p99 | max |\n| --- | --- | --- | --- | --- | --- | --- |"
            );
            for (series, s) in with_samples {
                let _ = writeln!(
                    r,
                    "| {} | {} | {:.2} | {:.2} | {:.2} | {:.2} | {:.2} |",
                    series.name, s.count, s.min, s.p50, s.p95, s.p99, s.max
                );
            }
            r.push('\n');
        }
        for note in &m.notes {
            let _ = writeln!(r, "- {note}");
        }
        match &m.outcome {
            Outcome::Met => {
                let _ = writeln!(r, "\nResult: **met**.");
            }
            Outcome::Missed(why) => {
                let _ = writeln!(r, "\nResult: **missed**: {why}.");
            }
            Outcome::NotMeasured(why) => {
                let _ = writeln!(r, "\nResult: **not measured**: {why}.");
            }
        }
    }
    let _ = writeln!(r, "\n## Open items\n");
    let items = open_items(machine, measurements);
    if items.is_empty() {
        let _ = writeln!(r, "None: every target was measured and met on this machine.");
    }
    for item in items {
        let _ = writeln!(r, "- {item}");
    }
    r
}

/// Every raw sample as CSV: requirement, series, index, value, unit.
pub(crate) fn render_samples(measurements: &[Measurement]) -> String {
    let mut csv = String::from("requirement,series,index,value,unit\n");
    for m in measurements {
        for series in &m.series {
            for (index, value) in series.values.iter().enumerate() {
                let _ = writeln!(
                    csv,
                    "{},{},{index},{value:.3},{}",
                    m.target.requirement,
                    series.name,
                    m.target.unit.symbol()
                );
            }
        }
    }
    csv
}

/// `target/qualification` (from this test binary's place, `target/<profile>/deps/`), or [`DIR_VAR`].
pub(crate) fn output_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os(DIR_VAR) {
        return PathBuf::from(dir);
    }
    let exe = std::env::current_exe().unwrap();
    // target/<profile>/deps/knshd-<hash> → target/
    exe.ancestors().nth(3).unwrap().join("qualification")
}

/// Writes `text` as `name` in [`output_dir`], and answers where.
pub(crate) fn write(name: &str, text: &str) -> PathBuf {
    let dir = output_dir();
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join(name);
    std::fs::write(&path, text).unwrap();
    path
}

#[cfg(test)]
mod tests {
    use super::*;

    const DECISION: Target = Target {
        requirement: "NFR-PERF-01",
        text: "decision p95 < 5 ms",
        unit: Unit::Ms,
        bound: Some(5.0),
    };

    fn measured(figure: f64, target: Target) -> Measurement {
        Measurement {
            figure_label: "p95".to_owned(),
            figure: Some(figure),
            series: vec![Series::new("lines, all", vec![1.0, 2.0, figure])],
            ..Measurement::new(target)
        }
        .judge()
    }

    fn apple() -> Machine {
        Machine {
            model: "MacBookPro18,3".into(),
            cpu: "Apple M1 Pro".into(),
            arch: "arm64".into(),
            build: "release".into(),
            macos: "26.6.2 (25G83)".into(),
            ..Machine::default()
        }
    }

    // NFR-PERF-01 – NFR-PERF-08 are all written "under": a figure equal to its bound is a miss, and the miss carries
    // the figure as measured, not rounded.
    #[test]
    fn bound_is_strict_and_misses_keep_their_figure() {
        assert_eq!(measured(4.99, DECISION).outcome, Outcome::Met);
        let Outcome::Missed(why) = measured(5.0, DECISION).outcome else {
            panic!("equal to the bound passed");
        };
        assert!(why.contains("5.00 ms, not under 5 ms"), "{why}");
    }

    // A failed check makes a miss even when the figure is fast: a measurement that did not measure what it claims
    // never passes.
    #[test]
    fn failed_check_is_a_miss_whatever_the_figure() {
        let mut m = measured(1.0, DECISION);
        m.failed_checks.push("a line did not run".to_owned());
        assert_eq!(m.judge().outcome, Outcome::Missed("a line did not run".to_owned()));
        let empty = Measurement::new(DECISION).judge();
        assert!(matches!(empty.outcome, Outcome::NotMeasured(_)));
        // A target without a bound is decided by its checks alone.
        let property = Target {
            bound: None,
            ..DECISION
        };
        assert_eq!(measured(1e9, property).outcome, Outcome::Met);
    }

    // KNSH-076: the report records the machine, the macOS version and the raw numbers, and lists every miss.
    #[test]
    fn report_records_machine_numbers_and_misses() {
        let missed = measured(7.25, DECISION);
        let memory = Target {
            requirement: "NFR-PERF-08",
            text: "idle memory < 50 MB",
            unit: Unit::Mb,
            bound: Some(50.0),
        };
        let not = Measurement::not_measured(memory, "no GUI session");
        let report = render(&apple(), &[measured(1.0, DECISION), missed.clone(), not.clone()]);
        for needle in [
            "Apple M1 Pro",
            "MacBookPro18,3",
            "26.6.2 (25G83)",
            "| NFR-PERF-01 | decision p95 < 5 ms | p95 | 1.00 ms | met |",
            "| NFR-PERF-01 | decision p95 < 5 ms | p95 | 7.25 ms | **missed** |",
            "| lines; all | 3 | 1.00 | 2.00 | 7.25 | 7.25 | 7.25 |",
            "- NFR-PERF-01 missed: p95 is 7.25 ms, not under 5 ms",
            "- NFR-PERF-08 not measured: no GUI session",
        ] {
            assert!(report.contains(needle), "missing {needle:?} in\n{report}");
        }
        let csv = render_samples(&[missed]);
        assert!(csv.starts_with("requirement,series,index,value,unit\n"));
        assert!(csv.contains("NFR-PERF-01,lines; all,2,7.250,ms\n"), "{csv}");
    }

    // A run off Apple silicon, or of a debug build, never qualifies, even when every figure is met.
    #[test]
    fn wrong_machine_or_build_is_an_open_item() {
        let met = [measured(1.0, DECISION)];
        assert_eq!(open_items(&apple(), &met), Vec::<String>::new());
        let intel = Machine {
            arch: "x86_64".into(),
            cpu: "Intel".into(),
            ..apple()
        };
        assert!(open_items(&intel, &met)[0].contains("Apple silicon"));
        let debug = Machine {
            build: "debug".into(),
            ..apple()
        };
        assert!(open_items(&debug, &met)[0].contains("release build"));
        assert!(render(&apple(), &met).contains("None: every target was measured and met"));
    }
}
