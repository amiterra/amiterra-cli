use std::io::{stdout, IsTerminal, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{sleep, spawn, JoinHandle};
use std::time::{Duration, Instant};

/// Visual glyph constants for consistent terminal iconography across platforms.
pub struct Glyphs;

impl Glyphs {
    pub const TICK: &'static str = "✔";
    pub const CROSS: &'static str = "✖";
    pub const BULLET: &'static str = "•";
    pub const BULLET_ACTIVE: &'static str = "●";
    pub const BULLET_INACTIVE: &'static str = "○";
    pub const CHEVRON: &'static str = "›";
    pub const DOT: &'static str = "•";
    pub const WARN: &'static str = "!";
    pub const PROMPT: &'static str = "?";
}

/// Detects whether styled ANSI escapes should be emitted based on standard terminal etiquette.
/// Honors `NO_COLOR`, `CLICOLOR`, `CLICOLOR_FORCE`, `TERM=dumb`, and `stdout().is_terminal()`.
pub fn is_color_enabled() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    if std::env::var("TERM").as_deref() == Ok("dumb") {
        return false;
    }
    if std::env::var("CLICOLOR").as_deref() == Ok("0") {
        return false;
    }
    if let Ok(force) = std::env::var("CLICOLOR_FORCE")
        && force != "0" {
            return true;
    }
    stdout().is_terminal()
}

/// Checks if stdout is an interactive terminal capable of live line clearing and spinners.
pub fn is_interactive() -> bool {
    stdout().is_terminal() && is_color_enabled()
}

// -----------------------------------------------------------------------------
// Typography & Color Helpers (Restrained Palette)
// -----------------------------------------------------------------------------

pub struct Palette;

impl Palette {
    pub fn cyan(s: &str) -> String {
        cyan(s)
    }
    pub fn bold_cyan(s: &str) -> String {
        bold_cyan(s)
    }
    pub fn green(s: &str) -> String {
        green(s)
    }
    pub fn bold_green(s: &str) -> String {
        bold_green(s)
    }
    pub fn yellow(s: &str) -> String {
        yellow(s)
    }
    pub fn bold_yellow(s: &str) -> String {
        bold_yellow(s)
    }
    pub fn red(s: &str) -> String {
        red(s)
    }
    pub fn bold_red(s: &str) -> String {
        bold_red(s)
    }
    pub fn dim(s: &str) -> String {
        dim(s)
    }
    pub fn bold(s: &str) -> String {
        bold(s)
    }
}

pub fn cyan(s: &str) -> String {
    if is_color_enabled() {
        format!("\x1b[36m{}\x1b[0m", s)
    } else {
        s.to_string()
    }
}

pub fn bold_cyan(s: &str) -> String {
    if is_color_enabled() {
        format!("\x1b[1;36m{}\x1b[0m", s)
    } else {
        s.to_string()
    }
}

pub fn green(s: &str) -> String {
    if is_color_enabled() {
        format!("\x1b[32m{}\x1b[0m", s)
    } else {
        s.to_string()
    }
}

pub fn bold_green(s: &str) -> String {
    if is_color_enabled() {
        format!("\x1b[1;32m{}\x1b[0m", s)
    } else {
        s.to_string()
    }
}

pub fn yellow(s: &str) -> String {
    if is_color_enabled() {
        format!("\x1b[33m{}\x1b[0m", s)
    } else {
        s.to_string()
    }
}

pub fn bold_yellow(s: &str) -> String {
    if is_color_enabled() {
        format!("\x1b[1;33m{}\x1b[0m", s)
    } else {
        s.to_string()
    }
}

pub fn red(s: &str) -> String {
    if is_color_enabled() {
        format!("\x1b[31m{}\x1b[0m", s)
    } else {
        s.to_string()
    }
}

pub fn bold_red(s: &str) -> String {
    if is_color_enabled() {
        format!("\x1b[1;31m{}\x1b[0m", s)
    } else {
        s.to_string()
    }
}

pub fn dim(s: &str) -> String {
    if is_color_enabled() {
        format!("\x1b[90m{}\x1b[0m", s)
    } else {
        s.to_string()
    }
}

pub fn bold(s: &str) -> String {
    if is_color_enabled() {
        format!("\x1b[1m{}\x1b[0m", s)
    } else {
        s.to_string()
    }
}

// -----------------------------------------------------------------------------
// Live Micro-Feedback Spinner
// -----------------------------------------------------------------------------

const SPINNER_FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

pub struct Spinner {
    message: String,
    start: Instant,
    active: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}

impl Spinner {
    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn start(message: impl Into<String>) -> Self {
        let msg = message.into();
        let start = Instant::now();

        if is_interactive() {
            let active = Arc::new(AtomicBool::new(true));
            let active_clone = active.clone();
            let thread_msg = msg.clone();

            let handle = spawn(move || {
                let mut frame_idx = 0;
                // Hide cursor
                let _ = stdout().write_all(b"\x1b[?25l");
                let _ = stdout().flush();

                while active_clone.load(Ordering::Relaxed) {
                    let frame = SPINNER_FRAMES[frame_idx % SPINNER_FRAMES.len()];
                    frame_idx += 1;
                    let elapsed = start.elapsed();
                    let sec_str = format!("{:.1}s", elapsed.as_secs_f32());

                    // \r + clear line (\x1b[2K)
                    let line = format!(
                        "\r\x1b[2K  {} {} {}",
                        cyan(frame),
                        thread_msg,
                        dim(&format!("({})", sec_str))
                    );
                    let _ = stdout().write_all(line.as_bytes());
                    let _ = stdout().flush();

                    sleep(Duration::from_millis(80));
                }

                // Restore cursor
                let _ = stdout().write_all(b"\x1b[?25h");
                let _ = stdout().flush();
            });

            Self {
                message: msg,
                start,
                active,
                handle: Some(handle),
            }
        } else {
            println!("  • {}...", msg);
            Self {
                message: msg,
                start,
                active: Arc::new(AtomicBool::new(false)),
                handle: None,
            }
        }
    }

    pub fn success(mut self, final_message: &str) {
        self.stop();
        let elapsed = self.start.elapsed();
        let dur_str = format!("[{:.1}s]", elapsed.as_secs_f32());
        if is_interactive() {
            println!(
                "\r\x1b[2K  {} {} {}",
                bold_green(Glyphs::TICK),
                final_message,
                dim(&dur_str)
            );
        } else {
            println!("  ✔ {} {}", final_message, dim(&dur_str));
        }
    }

    pub fn fail(mut self, error_message: &str) {
        self.stop();
        let elapsed = self.start.elapsed();
        let dur_str = format!("[{:.1}s]", elapsed.as_secs_f32());
        if is_interactive() {
            println!(
                "\r\x1b[2K  {} {} {}",
                bold_red(Glyphs::CROSS),
                error_message,
                dim(&dur_str)
            );
        } else {
            println!("  ✖ {} {}", error_message, dim(&dur_str));
        }
    }

    fn stop(&mut self) {
        self.active.store(false, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
        if is_interactive() {
            let _ = stdout().write_all(b"\r\x1b[2K");
            let _ = stdout().flush();
        }
    }
}

impl Drop for Spinner {
    fn drop(&mut self) {
        self.stop();
        if is_interactive() {
            let _ = stdout().write_all(b"\x1b[?25h");
            let _ = stdout().flush();
        }
    }
}

// -----------------------------------------------------------------------------
// High-Level UI Elements
// -----------------------------------------------------------------------------

pub struct Ui;

impl Ui {
    /// Renders the top command banner in clean, authoritative typography.
    pub fn header(title: &str, subtitle: &str) {
        let el = if is_color_enabled() { "\x1b[K" } else { "" };
        println!("{}", el);
        println!(
            "{} {} {}{}",
            bold("amiterra"),
            cyan(Glyphs::CHEVRON),
            bold(title),
            el
        );
        if !subtitle.is_empty() {
            println!("  {}{}", dim(subtitle), el);
        }
        println!("{}", el);
    }

    /// Renders an instantaneous completed step with optional duration tag.
    pub fn step_done(message: &str, elapsed: Option<Duration>) {
        if let Some(dur) = elapsed {
            let dur_str = format!("[{:.1}s]", dur.as_secs_f32());
            println!("  {} {} {}", bold_green(Glyphs::TICK), message, dim(&dur_str));
        } else {
            println!("  {} {}", bold_green(Glyphs::TICK), message);
        }
    }

    /// Renders a diagnostic warning step.
    pub fn step_warn(message: &str) {
        println!("  {} {}", bold_yellow(Glyphs::WARN), message);
    }

    /// Renders a diagnostic failure/error step.
    pub fn step_err(message: &str) {
        println!("  {} {}", bold_red(Glyphs::CROSS), message);
    }

    /// Renders an informational bullet item.
    pub fn step_info(label: &str, value: &str) {
        println!("  {} {:<22} {}", dim(Glyphs::DOT), dim(label), value);
    }

    /// Starts a live animated micro-feedback spinner for long-running steps.
    pub fn spinner(message: impl Into<String>) -> Spinner {
        Spinner::start(message)
    }

    /// Renders the Receipt Card pattern with aligned columns and a fully closed rounded border.
    pub fn card(title: &str, items: &[(&str, &str)]) {
        let max_label_len = items
            .iter()
            .map(|(label, _)| label.chars().count())
            .max()
            .unwrap_or(12)
            .max(14);

        let styled_items: Vec<(&str, String)> = items
            .iter()
            .map(|(label, val)| (*label, Self::colorize_status(val)))
            .collect();

        let title_len = title.chars().count();
        let max_content_width = styled_items
            .iter()
            .map(|(_, val)| 2 + max_label_len + 2 + Self::visible_width(val) + 4)
            .max()
            .unwrap_or(70);

        let inner_width = max_content_width.max(title_len + 6).max(72);
        let border_len = inner_width.saturating_sub(title_len + 3);

        let top_border = format!("{}╮", "─".repeat(border_len));
        let bottom_border = format!("{}╯", "─".repeat(inner_width));
        let el = if is_color_enabled() { "\x1b[K" } else { "" };

        println!("{}", el);
        println!(
            "{}{}{}{}{}",
            dim("╭─ "),
            bold(title),
            dim(" "),
            dim(&top_border),
            el
        );
        println!("{}{}{}{}", dim("│"), " ".repeat(inner_width), dim("│"), el);

        for (label, value) in &styled_items {
            let label_pad = " ".repeat(max_label_len.saturating_sub(label.chars().count()));
            let v_len = Self::visible_width(value);
            let content_used = 2 + max_label_len + 2 + v_len;
            let right_pad = " ".repeat(inner_width.saturating_sub(content_used));

            println!(
                "{}  {}{}  {}{}{}{}",
                dim("│"),
                label,
                label_pad,
                value,
                right_pad,
                dim("│"),
                el
            );
        }

        println!("{}{}{}{}", dim("│"), " ".repeat(inner_width), dim("│"), el);
        println!("{}{}{}", dim("╰"), dim(&bottom_border), el);
        println!("{}", el);
    }

    /// Formats actionable next steps ready for developer copy-pasting.
    pub fn next_steps(heading: &str, steps: &[&str]) {
        println!("{}", bold(heading));
        let max_cmd_len = steps
            .iter()
            .filter_map(|s| {
                if s.starts_with('$') {
                    None
                } else {
                    s.find("  ").map(|idx| s[..idx].trim().chars().count())
                }
            })
            .max()
            .unwrap_or(10)
            .max(10);
        let target_width = max_cmd_len + 2;

        for step in steps {
            if let Some(cmd) = step.strip_prefix("$ ") {
                println!("  {} {}", dim("$"), cyan(cmd));
            } else if step.starts_with('$') {
                println!("  {}", cyan(step));
            } else if let Some(idx) = step.find("  ") {
                let cmd = step[..idx].trim();
                let desc = step[idx..].trim();
                let pad = " ".repeat(target_width.saturating_sub(cmd.chars().count()));
                println!(
                    "  {} {}{} {}",
                    cyan(Glyphs::CHEVRON),
                    bold(cmd),
                    pad,
                    dim(desc)
                );
            } else {
                println!("  {} {}", cyan(Glyphs::CHEVRON), step);
            }
        }
        println!();
    }

/// Calculates visible terminal width by ignoring ANSI escape sequences.
pub fn visible_width(s: &str) -> usize {
    let mut in_escape = false;
    let mut width = 0;
    for c in s.chars() {
        if c == '\x1b' {
            in_escape = true;
        } else if in_escape {
            if c.is_ascii_alphabetic() {
                in_escape = false;
            }
        } else {
            width += 1;
        }
    }
    width
}

/// Applies contextual semantic colors to status labels, URLs, and indicators.
pub fn colorize_status(s: &str) -> String {
    let mut res = s.to_string();

    // Normalize text representations first
    res = res.replace("Stopped / Inactive", "○ inactive (stopped)");

    if !is_color_enabled() {
        return res;
    }
    // If string already contains custom ANSI codes, respect caller styling
    if res.contains("\x1b[") {
        return res;
    }

    // Positive / active statuses
    res = res.replace("● healthy", &bold_green("● healthy"));
    res = res.replace("● active", &bold_green("● active"));
    res = res.replace("● online", &bold_green("● online"));
    res = res.replace("● ready", &bold_green("● ready"));
    res = res.replace("● supported", &bold_green("● supported"));
    res = res.replace("● available", &bold_green("● available"));
    res = res.replace("READY FOR DEPLOYMENT", &bold_green("READY FOR DEPLOYMENT"));
    res = res.replace(" READY", &format!(" {}", bold_green("READY")));

    // Warnings / stopped / ineligible
    res = res.replace("○ inactive", &dim("○ inactive"));
    res = res.replace("○ ineligible", &dim("○ ineligible"));
    res = res.replace("○ not ready", &dim("○ not ready"));
    res = res.replace("○ not initialized", &dim("○ not initialized"));
    res = res.replace("○ not detected", &dim("○ not detected"));
    res = res.replace("○ none detected", &dim("○ none detected"));
    res = res.replace("○ missing", &dim("○ missing"));
    res = res.replace("○ requires", &dim("○ requires"));
    res = res.replace("● stopped", &yellow("● stopped"));
    res = res.replace("(daemon stopped)", &yellow("(daemon stopped)"));
    res = res.replace("● degraded", &bold_yellow("● degraded"));

    // Errors / failures
    res = res.replace("● unhealthy", &bold_red("● unhealthy"));
    res = res.replace("NOT READY", &bold_red("NOT READY"));

    // Automatically dim secondary metadata in parentheses
    if let (Some(start), Some(end)) = (res.find('('), res.rfind(')'))
        && start < end {
            let inner = &res[start..=end];
            if !inner.contains("\x1b[") {
                let dimmed = dim(inner);
                res = format!("{}{}{}", &res[..start], dimmed, &res[end + 1..]);
            }
    }

    // URLs (highlighted in cyan)
    if res.contains("https://127.0.0.1:6443") {
        res = res.replace("https://127.0.0.1:6443", &cyan("https://127.0.0.1:6443"));
    }

    res
}

    /// Renders an actionable error block (What happened -> Why -> How to fix -> Docs).
    pub fn error_box(what: &str, why: &str, steps: &[&str], docs_url: Option<&str>) {
        println!();
        println!("{} {}", bold_red(Glyphs::CROSS), bold(what));
        println!();
        println!("{}", dim("Why this happened:"));
        for line in why.lines() {
            println!("  {}", line);
        }
        println!();

        if !steps.is_empty() {
            println!("{}", dim("Suggested next steps:"));
            for step in steps {
                if step.starts_with('$') {
                    println!("    {}", cyan(step));
                } else if step.starts_with("•") || step.starts_with("›") {
                    println!("  {}", step);
                } else {
                    println!("  {} {}", cyan(Glyphs::CHEVRON), step);
                }
            }
            println!();
        }

        if let Some(url) = docs_url {
            println!("{}", dim("Documentation:"));
            println!("  {}", cyan(url));
            println!();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_glyphs_and_palette_basic() {
        assert_eq!(Glyphs::TICK, "✔");
        assert_eq!(Glyphs::CROSS, "✖");
        assert_eq!(Glyphs::BULLET, "•");
        assert_eq!(Glyphs::CHEVRON, "›");

        let formatted = Palette::cyan("test");
        assert!(formatted.contains("test"));
        let green_str = Palette::bold_green("ok");
        assert!(green_str.contains("ok"));
        let warn_str = Palette::yellow("warn");
        assert!(warn_str.contains("warn"));
        let red_str = Palette::bold_red("err");
        assert!(red_str.contains("err"));
        let dim_str = Palette::dim("subtle");
        assert!(dim_str.contains("subtle"));
    }

    #[test]
    fn test_card_rendering_runs() {
        let items = [
            ("Network Topology", "● Private NAT (192.168.1.165 on en0, Public NAT: 197.151.129.214)"),
            ("WireGuard Encryption", "○ Optional (Private L2 mesh isolated)"),
            ("Cluster Node IP", "192.168.1.165"),
            ("Pod Subnet", "10.42.0.0/16 (Collision-free verified)"),
            ("Service Subnet", "10.43.0.0/16"),
            ("TLS SANs", "127.0.0.1, localhost, kubernetes, ... (+6 more)"),
        ];
        Ui::card("Amiterra Network Auto-Discovery", &items);
    }

    #[test]
    fn test_error_box_runs() {
        Ui::error_box(
            "Test Error",
            "Because of something.",
            &["Do step 1", "$ ami up", "• Note something"],
            Some("https://amiterra.io"),
        );
    }

    #[test]
    fn test_header_and_steps_run() {
        Ui::header("Test Header", "Test Subtitle");
        Ui::step_done("Step completed", Some(Duration::from_millis(150)));
        Ui::step_done("Instant step", None);
        Ui::step_warn("Step with warning");
        Ui::step_err("Step with error");
        Ui::step_info("Info key", "Info value");
        Ui::next_steps("What to do next:", &["Run this", "$ ami status"]);
    }

    #[test]
    fn test_spinner_lifecycle() {
        let sp = Ui::spinner("Testing spinner lifecycle");
        assert_eq!(sp.message(), "Testing spinner lifecycle");
        sp.success("Testing completed");

        let sp2 = Ui::spinner("Testing fail lifecycle");
        sp2.fail("Testing failed as expected");
    }

    #[test]
    fn test_visible_width_and_colorize_status() {
        let plain = "● healthy (control plane online)";
        let colored = Ui::colorize_status(plain);
        let v_len = Ui::visible_width(&colored);
        assert_eq!(v_len, plain.chars().count());

        let url_plain = "https://127.0.0.1:6443 (mTLS secured)";
        let url_colored = Ui::colorize_status(url_plain);
        assert_eq!(Ui::visible_width(&url_colored), url_plain.chars().count());
    }
}
