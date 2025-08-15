use anyhow::{anyhow, bail, Context, Result};
use clap::{ArgAction, Parser};
use console::{style, Style};
use directories::ProjectDirs;
use dialoguer::{theme::ColorfulTheme, Confirm, FuzzySelect, Input, MultiSelect};
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet, HashMap},
    ffi::OsStr,
    fs::{self, File, OpenOptions},
    io::{Cursor, Read, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::UNIX_EPOCH,
};
use tar::{Archive, Builder, EntryType, Header};
use walkdir::WalkDir;

// -------------------- CLI --------------------

#[derive(Parser, Debug)]
#[command(name="tar-append", about="Tar Archive Manager (Rust) with Gum aesthetics")]
struct Cli {
    /// Fast tree view (uses cache; top-level only)
    #[arg(long)]
    list: bool,

    /// Full tree with ZIP peeking and folder-first sorting
    #[arg(long = "list-all")]
    list_all: bool,

    /// Add files/dirs (default if no mode is given)
    #[arg(long)]
    append: bool,

    /// Remove files/dirs from archive (rebuilds TAR)
    #[arg(long)]
    remove: bool,

    /// Extract a single .zip member from tar
    #[arg(long = "extract-zip")]
    extract_zip: bool,

    /// Also extract the contents of that ZIP (non-interactive)
    #[arg(long = "extract-zip-contents", action = ArgAction::SetTrue)]
    extract_zip_contents: bool,

    /// Destination for --extract-zip
    #[arg(long = "into")]
    into_dir: Option<PathBuf>,

    /// Prefix added items inside archive (append mode)
    #[arg(long = "target")]
    target_dir: Option<String>,

    /// Specific .zip member path inside archive (for --extract-zip)
    #[arg(long = "member")]
    member: Option<String>,

    /// Skip prompts (non-interactive)
    #[arg(long, action = ArgAction::SetTrue)]
    yes: bool,

    /// Verbose logging
    #[arg(short, long, action = ArgAction::SetTrue)]
    verbose: bool,

    /// Count entries first (parity flag; spinner shown)
    #[arg(long, action = ArgAction::SetTrue)]
    prepass: bool,

    /// Archive file (.tar)
    archive: PathBuf,

    /// Extra args (paths to add/remove)
    #[arg(trailing_var_arg = true)]
    rest: Vec<PathBuf>,
}

// -------------------- ignore helpers --------------------

fn is_junk_component(name: &str) -> bool {
    name == ".DS_Store" || name == "__MACOSX" || name.eq_ignore_ascii_case("Thumbs.db")
}
fn is_junk_component_os(name: &OsStr) -> bool {
    is_junk_component(&name.to_string_lossy())
}
fn should_ignore_name(name: &str) -> bool {
    let n = name.trim_start_matches("./");
    n == ".DS_Store"
    || n.ends_with("/.DS_Store")
    || n.starts_with("__MACOSX/")
    || n.eq_ignore_ascii_case("Thumbs.db")
    || n.ends_with("/Thumbs.db")
}

// -------------------- Gum-like UI layer --------------------

struct UI {
    gum: Option<PathBuf>,
    yes: bool,
    theme: ColorfulTheme,
}

impl UI {
    fn new(yes: bool) -> Self {
        let gum = which::which("gum").ok();
        let mut theme = ColorfulTheme::default();

        // ColorfulTheme expects StyledObject<String> for prefixes and Style for values_style
        theme.prompt_prefix = console::style(String::from("❯")).green().bold();
        theme.success_prefix = console::style(String::from("✔")).green().bold();
        theme.error_prefix = console::style(String::from("✖")).red().bold();
        theme.values_style = Style::new();
        theme.active_item_prefix = console::style(String::from("›")).cyan().bold();
        theme.inactive_item_prefix = console::style(String::from(" "));
        theme.checked_item_prefix = console::style(String::from("✔")).green().bold();
        theme.unchecked_item_prefix = console::style(String::from(" "));

        Self { gum, yes, theme }
    }

    fn note(&self, s: &str) {
        if let Some(p) = &self.gum {
            let _ = Command::new(p)
            .arg("style").arg("--border=none").arg("--padding").arg("0 1")
            .arg(format!("🔎 {s}"))
            .status();
        } else {
            println!(" 🔎 {s}");
        }
    }

    fn box_lines(&self, lines: &[String]) {
        if let Some(p) = &self.gum {
            let mut child = Command::new(p)
            .arg("style").arg("--border=rounded").arg("--bold")
            .stdin(Stdio::piped())
            .spawn()
            .ok();
            if let Some(ch) = child.as_mut() {
                if let Some(stdin) = ch.stdin.as_mut() {
                    for l in lines { let _ = writeln!(stdin, "{l}"); }
                }
                let _ = ch.wait();
            }
        } else {
            print_tree_box(lines);
        }
    }

    fn spinner<R>(&self, title: &str, f: impl FnOnce() -> R) -> R {
        if self.gum.is_some() {
            self.note(title);
            f()
        } else {
            let pb = ProgressBar::new_spinner();
            pb.enable_steady_tick(std::time::Duration::from_millis(80));
            pb.set_style(
                ProgressStyle::with_template("{spinner} {msg}")
                .unwrap()
                .tick_strings(&["⠋","⠙","⠸","⠴","⠦","⠇"])
            );
            pb.set_message(title.to_string());
            let out = f();
            pb.finish_and_clear();
            out
        }
    }

    /// Determinate progress bar (items count).
    fn progress(&self, title: &str, len: u64) -> ProgressBar {
        let pb = ProgressBar::new(len);
        pb.set_style(
            ProgressStyle::with_template("{bar:30.cyan/blue} {pos}/{len} {msg}")
            .unwrap()
            .progress_chars("█▉▊▋▌▍▎▏ ")
        );
        pb.set_message(title.to_string());
        pb
    }

    /// Determinate progress bar for bytes with MB/s.
    fn progress_bytes(&self, title: &str, total_bytes: u64) -> ProgressBar {
        let pb = ProgressBar::new(total_bytes);
        pb.set_style(
            ProgressStyle::with_template(
                "{spinner:.green} {msg} [{bar:30.cyan/blue}] {bytes:>8}/{total_bytes:8}  @ {per_sec}"
            )
            .unwrap()
            .progress_chars("█▉▊▋▌▍▎▏ ")
        );
        pb.set_message(title.to_string());
        pb
    }

    /// Quickly “replay” a determinate progress bar over `len` steps (for cache hits).
    fn replay_progress(&self, title: &str, len: u64, total_ms: u64) {
        use std::thread::sleep;
        use std::time::Duration;

        let pb = self.progress(title, len.max(1));
        if len == 0 {
            pb.finish_and_clear();
            return;
        }
        let per_step = (total_ms.max(120)) / len.max(1);
        for i in 0..len {
            pb.set_message(format!("Cached… {}/{}", i + 1, len));
            pb.inc(1);
            sleep(Duration::from_millis(per_step.max(8)));
        }
        pb.finish_and_clear();
    }

    fn confirm(&self, prompt: &str) -> bool {
        if self.yes { return true; }
        if let Some(p) = &self.gum {
            let st = Command::new(p).arg("confirm").arg(prompt).status();
            return st.map(|s| s.success()).unwrap_or(false);
        }
        Confirm::with_theme(&self.theme)
        .with_prompt(prompt)
        .interact()
        .unwrap_or(false)
    }

    #[allow(dead_code)]
    fn input(&self, header: &str, placeholder: &str, default: &str) -> String {
        if let Some(p) = &self.gum {
            if !self.yes {
                if let Ok(out) = Command::new(p)
                    .arg("input")
                    .arg("--header").arg(header)
                    .arg("--placeholder").arg(placeholder)
                    .arg("--value").arg(default)
                    .output()
                    {
                        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                        if !s.is_empty() { return s; }
                    }
            }
        }
        Input::<String>::with_theme(&self.theme)
        .with_prompt(header.to_string())
        .default(default.to_string())
        .interact_text()
        .unwrap_or_else(|_| default.to_string())
    }

    #[allow(dead_code)]
    fn pick_one(&self, items: &[String], placeholder: &str) -> Option<String> {
        if items.is_empty() { return None; }
        if let Some(p) = &self.gum {
            if !self.yes {
                let mut child = Command::new(p)
                .arg("filter").arg("--placeholder").arg(placeholder)
                .stdin(Stdio::piped()).stdout(Stdio::piped())
                .spawn().ok()?;
                if let Some(stdin) = child.stdin.as_mut() {
                    for it in items { let _ = writeln!(stdin, "{it}"); }
                }
                let out = child.wait_with_output().ok()?;
                let pick = String::from_utf8_lossy(&out.stdout).trim().to_string();
                return if pick.is_empty() { None } else { Some(pick) };
            }
        }
        let idx = FuzzySelect::with_theme(&self.theme)
        .with_prompt(placeholder.to_string())
        .items(items)
        .default(0)
        .interact()
        .ok()?;
        Some(items[idx].clone())
    }

    fn choose_multi(&self, items: &[String], header: &str) -> Vec<String> {
        if items.is_empty() { return vec![]; }
        if let Some(p) = &self.gum {
            if !self.yes {
                let mut child = Command::new(p)
                .arg("choose").arg("--limit=0")
                .arg("--cursor=❌ ").arg("--header").arg(header)
                .stdin(Stdio::piped()).stdout(Stdio::piped())
                .spawn().ok();
                if let Some(mut ch) = child {
                    if let Some(stdin) = ch.stdin.as_mut() {
                        for it in items { let _ = writeln!(stdin, "{it}"); }
                    }
                    if let Ok(out) = ch.wait_with_output() {
                        return String::from_utf8_lossy(&out.stdout)
                        .lines().map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty()).collect();
                    }
                }
            }
        }
        let selections = MultiSelect::with_theme(&self.theme)
        .with_prompt(header.to_string())
        .items(items)
        .interact()
        .unwrap_or_default();
        selections.into_iter().map(|i| items[i].clone()).collect()
    }
}

// -------------------- util/log/size --------------------

fn vnote(v: bool, ui: &UI, msg: impl AsRef<str>) {
    if v { ui.note(msg.as_ref()); }
}

fn human_size(mut n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut idx = 0usize;
    let mut f = n as f64;
    while f >= 1024.0 && idx < UNITS.len() - 1 {
        f /= 1024.0;
        idx += 1;
    }
    if idx == 0 { format!("{n} B") } else { format!("{:.1} {}", f, UNITS[idx]) }
}

fn colorize_size(s: &str) -> String {
    // bright orange-ish (xterm 208), bold
    format!("{}", console::style(s).color256(208).bold())
}

// -------------------- cache types --------------------

#[derive(Serialize, Deserialize, Default)]
struct FullCache {
    lines: Vec<String>,
    tar_sig: String,
    included_zip_keys: BTreeSet<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
struct ZipEntry {
    path: String, // "./foo/bar" (dirs end with '/')
    size: u64,    // uncompressed for files, 0 for dirs
    is_dir: bool,
}

#[derive(Serialize, Deserialize, Default)]
struct ZipCache {
    entries: Vec<ZipEntry>,
    key: String,
}

struct CachePaths {
    tar_dir: PathBuf,
    fast_txt: PathBuf,
    full_json: PathBuf,
    zip_dir: PathBuf,
}

// -------------------- fs helpers --------------------

fn sha256_hex(bytes: impl AsRef<[u8]>) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn cache_base_dir() -> Result<PathBuf> {
    if let Some(proj) = ProjectDirs::from("dev", "tarappend", "tar-append") {
        Ok(proj.cache_dir().to_path_buf())
    } else {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("/tmp"));
        Ok(home.join(".cache").join("tar-append"))
    }
}

fn file_mtime_size(p: &Path) -> Result<(u64, u64)> {
    let md = fs::metadata(p).with_context(|| format!("stat {}", p.display()))?;
    let size = md.len();
    let mtime = md.modified()?.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    Ok((mtime, size))
}

fn cache_paths(archive: &Path) -> Result<CachePaths> {
    let (mtime, size) = file_mtime_size(archive)?;
    let sig = format!("{}|{}|{}", archive.display(), mtime, size);
    let hash = sha256_hex(sig.as_bytes());
    let base = cache_base_dir()?;
    let tar_dir = base.join(hash);
    fs::create_dir_all(&tar_dir)?;
    Ok(CachePaths {
        tar_dir: tar_dir.clone(),
       fast_txt: tar_dir.join("list.fast"),
       full_json: tar_dir.join("list.full.json"),
       zip_dir: tar_dir.join("zip"),
    })
}

fn write_fast_cache(cache: &CachePaths, lines: &[String]) -> Result<()> {
    fs::create_dir_all(&cache.tar_dir)?;
    fs::write(&cache.fast_txt, lines.join("\n"))?;
    Ok(())
}
fn read_fast_cache(cache: &CachePaths) -> Option<Vec<String>> {
    let s = fs::read_to_string(&cache.fast_txt).ok()?;
    Some(s.lines().map(|x| x.to_string()).collect())
}

fn write_full_cache(cache: &CachePaths, fc: &FullCache) -> Result<()> {
    fs::create_dir_all(&cache.tar_dir)?;
    fs::create_dir_all(&cache.zip_dir)?;
    fs::write(&cache.full_json, serde_json::to_vec(fc)?)?;
    Ok(())
}
fn read_full_cache(cache: &CachePaths) -> Option<FullCache> {
    let b = fs::read(&cache.full_json).ok()?;
    serde_json::from_slice(&b).ok()
}

// -------------------- tar/zip + sorting --------------------

/// Return:
/// - `names`: normalized paths ("./...", dir ends with '/'; junk filtered)
/// - `zips`: map zip path -> (size, mtime) from tar header
/// - `file_sizes`: map tar file path -> size (directories not included)
fn read_tar_entries(
    archive: &Path
) -> Result<(Vec<String>, BTreeMap<String, (u64, u64)>, BTreeMap<String, u64>)> {
    let f = File::open(archive)?;
    let mut ar = Archive::new(f);
    let mut names = Vec::new();
    let mut zips = BTreeMap::new();
    let mut file_sizes = BTreeMap::new();

    for entry in ar.entries()? {
        let mut e = entry?;
        let mut path = e.path()?.to_string_lossy().into_owned();
        if !path.starts_with("./") && !path.starts_with('/') {
            path = format!("./{}", path);
        }
        let is_dir = e.header().entry_type().is_dir();
        if is_dir && !path.ends_with('/') {
            path.push('/');
        }
        if should_ignore_name(&path) {
            continue; // ignore junk
        }
        names.push(path.clone());
        if !is_dir {
            let sz = e.header().size().unwrap_or(0);
            file_sizes.insert(path.clone(), sz);
        }
        if path.to_ascii_lowercase().ends_with(".zip") && !path.ends_with('/') {
            let size = e.header().size().unwrap_or(0);
            let mtime = e.header().mtime().unwrap_or(0);
            zips.insert(path, (size, mtime));
        }
    }
    Ok((names, zips, file_sizes))
}

fn sort_paths_folder_first(paths: &[String]) -> Vec<String> {
    let mut rows: Vec<(String, bool, String, String)> = Vec::with_capacity(paths.len());
    for p in paths {
        if p == "./" { continue; }
        let q = p.trim_start_matches("./");
        let is_file = !q.ends_with('/');
        let parent = q.rsplit_once('/').map(|(a, _)| a.to_string()).unwrap_or_default();
        let base = if is_file {
            q.rsplit_once('/').map(|(_, b)| b.to_string()).unwrap_or(q.to_string())
        } else {
            q.trim_end_matches('/').rsplit_once('/').map(|(_, b)| b.to_string())
            .unwrap_or(q.trim_end_matches('/').to_string())
        };
        rows.push((parent, is_file, base, p.clone()));
    }
    rows.sort_by(|a, b| {
        match a.0.cmp(&b.0) {
            Ordering::Equal => match a.1.cmp(&b.1) {
                Ordering::Equal => a.2.to_lowercase().cmp(&b.2.to_lowercase()),
                 other => other, // dirs (false) first
            },
            other => other,
        }
    });
    rows.into_iter().map(|(_,_,_,full)| full).collect()
}

/// Build a map of directory -> sum of contained file sizes (recursive)
fn accumulate_dir_sizes(paths: &[String], file_sizes: &BTreeMap<String, u64>) -> BTreeMap<String, u64> {
    let mut dir_sum: BTreeMap<String, u64> = BTreeMap::new();
    for (path, sz) in file_sizes {
        let clean = path.trim_start_matches("./");
        let mut acc = String::new();
        for comp in clean.split('/') {
            if comp.is_empty() { continue; }
            if !acc.is_empty() { acc.push('/'); }
            acc.push_str(comp);
            dir_sum
            .entry(format!("./{}/", acc))
            .and_modify(|v| *v += *sz)
            .or_insert(*sz);
        }
    }
    // ensure directories existing but empty still appear with 0
    for p in paths {
        if p.ends_with('/') {
            dir_sum.entry(p.clone()).or_insert(0);
        }
    }
    dir_sum
}

fn render_tree_with_sizes(paths: &[String], file_sizes: &BTreeMap<String, u64>, dir_sizes: &BTreeMap<String, u64>) -> Vec<String> {
    let mut out = Vec::new();
    for p in paths {
        let disp_clean = p.trim_start_matches("./").trim_end_matches('/').to_string();
        let depth = disp_clean.matches('/').count();
        let name = if p.ends_with('/') {
            format!("{}/", disp_clean.rsplit_once('/').map(|(_,b)| b).unwrap_or(&disp_clean))
        } else {
            disp_clean.rsplit_once('/').map(|(_,b)| b.to_string()).unwrap_or(disp_clean.clone())
        };
        let indent = " ".repeat(depth * 4);
        let size = if p.ends_with('/') {
            dir_sizes.get(p).cloned().unwrap_or(0)
        } else {
            file_sizes.get(p).cloned().unwrap_or(0)
        };
        let sz = colorize_size(&human_size(size));
        out.push(format!("{indent}{name}  — {}", sz));
    }
    out
}

fn read_member_bytes(archive: &Path, wanted: &str) -> Result<Vec<u8>> {
    let f = File::open(archive)?;
    let mut ar = Archive::new(f);
    for entry in ar.entries()? {
        let mut e = entry?;
        let path = e.path()?.to_string_lossy().into_owned();
        if path == wanted || format!("./{}", path) == wanted {
            let mut buf = Vec::with_capacity(e.header().size().unwrap_or(0) as usize);
            e.read_to_end(&mut buf)?;
            return Ok(buf);
        }
    }
    bail!("member not found: {wanted}");
}

/// List ZIP entries with a live progress bar. Returns entries with sizes.
fn list_zip_entries_with_progress(zip_bytes: &[u8], ui: &UI, title: &str) -> Result<Vec<ZipEntry>> {
    let cursor = Cursor::new(zip_bytes);
    let mut zr = zip::ZipArchive::new(cursor)?;
    let total = zr.len() as u64;

    let pb = ui.progress(title, total.max(1));
    let mut out = Vec::new();

    for i in 0..zr.len() {
        let f = zr.by_index(i)?;
        let is_dir = f.is_dir();
        let mut p = f.name().to_string();
        if is_dir && !p.ends_with('/') {
            p.push('/');
        }
        if !p.starts_with("./") { p = format!("./{p}"); }
        if !should_ignore_name(&p) {
            let size = if is_dir { 0 } else { f.size() };
            out.push(ZipEntry { path: p, size, is_dir });
        }
        let shown = f.name().rsplit('/').next().unwrap_or(f.name());
        pb.set_message(format!("Scanning: {}", shown));
        pb.inc(1);
    }

    pb.finish_and_clear();
    Ok(out)
}

// -------------------- tree box printer (gum-like) --------------------

fn print_tree_box(lines: &[String]) {
    if lines.is_empty() {
        println!("(no entries)");
        return;
    }
    let width = lines.iter().map(|s| s.len()).max().unwrap_or(0).min(95);
    let top = format!("╭{}╮", "─".repeat(width + 2));
    println!("{top}");
    for l in lines {
        let mut s = l.clone();
        if s.len() > width { s.truncate(width); }
        println!("│ {:<width$} │", s, width = width);
    }
    let bot = format!("╰{}╯", "─".repeat(width + 2));
    println!("{bot}");
}

// -------------------- list-all builder with spinner + per-zip cache --------------------

fn build_list_all(
    archive: &Path,
    paths_sorted: &[String],
    zips: &BTreeMap<String, (u64,u64)>,
                  file_sizes: &BTreeMap<String, u64>,
                  cache: &CachePaths,
                  tar_sig: &str,
                  ui: &UI,
                  verbose: bool,
) -> Result<FullCache> {
    // Pre-aggregate tar dir sizes (for top-level dirs)
    let tar_dir_sizes = accumulate_dir_sizes(paths_sorted, file_sizes);

    let mut lines = Vec::new();
    let mut included_zip_keys = BTreeSet::new();

    for p in paths_sorted {
        // print the item itself + size
        let disp_clean = p.trim_start_matches("./").trim_end_matches('/').to_string();
        let depth = disp_clean.matches('/').count();
        let name = if p.ends_with('/') {
            format!("{}/", disp_clean.rsplit_once('/').map(|(_,b)| b).unwrap_or(&disp_clean))
        } else {
            disp_clean.rsplit_once('/').map(|(_,b)| b.to_string()).unwrap_or(disp_clean.clone())
        };
        let indent = " ".repeat(depth * 4);
        let size_here = if p.ends_with('/') {
            tar_dir_sizes.get(p).cloned().unwrap_or(0)
        } else {
            file_sizes.get(p).cloned().unwrap_or(0)
        };
        let szs = colorize_size(&human_size(size_here));
        lines.push(format!("{indent}{name}  — {}", szs));

        // expand ZIPs
        if p.to_ascii_lowercase().ends_with(".zip") && !p.ends_with('/') {
            if let Some((sz, mt)) = zips.get(p) {
                let zip_key = format!("{}|{}|{}|{}", p, sz, mt, tar_sig);
                let zip_hash = sha256_hex(zip_key.as_bytes());
                included_zip_keys.insert(zip_hash.clone());
                fs::create_dir_all(&cache.zip_dir).ok();
                let zip_cache_file = cache.zip_dir.join(format!("{zip_hash}.json"));

                let entries: Vec<ZipEntry> = if zip_cache_file.exists() {
                    vnote(verbose, ui, &format!("zip-cache: HIT → {}", p));
                    let jc = fs::read(&zip_cache_file)?;
                    let z: ZipCache = serde_json::from_slice(&jc)?;
                    if z.key == zip_key && !z.entries.is_empty() {
                        let title = format!(
                            "ZIP {} (cached)",
                                            Path::new(p).file_name().unwrap().to_string_lossy()
                        );
                        ui.replay_progress(&title, z.entries.len() as u64, 400);
                        z.entries
                    } else {
                        vnote(verbose, ui, &format!("zip-cache: STALE → {}", p));
                        let bytes = read_member_bytes(archive, p)?;
                        let mut zentries = list_zip_entries_with_progress(
                            &bytes,
                            ui,
                            &format!("ZIP {} (rescan)", Path::new(p).file_name().unwrap().to_string_lossy()),
                        )?;
                        // sort folder-first within zip
                        zentries.sort_by(|a, b| {
                            let af = !a.is_dir;
                            let bf = !b.is_dir;
                            match (a.path.rsplit_once('/').map(|(d,_)| d).unwrap_or("")).cmp(
                                &b.path.rsplit_once('/').map(|(d,_)| d).unwrap_or("")
                            ) {
                                Ordering::Equal => match af.cmp(&bf) {
                                    Ordering::Equal => a.path.to_lowercase().cmp(&b.path.to_lowercase()),
                                         other => other,
                                },
                                other => other,
                            }
                        });
                        let new = ZipCache { entries: zentries.clone(), key: zip_key.clone() };
                        fs::write(&zip_cache_file, serde_json::to_vec(&new).unwrap()).unwrap();
                        zentries
                    }
                } else {
                    vnote(verbose, ui, &format!("zip-cache: MISS → {}", p));
                    let bytes = read_member_bytes(archive, p)?;
                    let mut zentries = list_zip_entries_with_progress(
                        &bytes,
                        ui,
                        &format!("ZIP {}", Path::new(p).file_name().unwrap().to_string_lossy()),
                    )?;
                    zentries.sort_by(|a, b| {
                        let af = !a.is_dir;
                        let bf = !b.is_dir;
                        match (a.path.rsplit_once('/').map(|(d,_)| d).unwrap_or("")).cmp(
                            &b.path.rsplit_once('/').map(|(d,_)| d).unwrap_or("")
                        ) {
                            Ordering::Equal => match af.cmp(&bf) {
                                Ordering::Equal => a.path.to_lowercase().cmp(&b.path.to_lowercase()),
                                     other => other,
                            },
                            other => other,
                        }
                    });
                    let new = ZipCache { entries: zentries.clone(), key: zip_key.clone() };
                    fs::write(&zip_cache_file, serde_json::to_vec(&new).unwrap()).unwrap();
                    zentries
                };

                // build zip dir size aggregates
                let mut zip_file_sizes: HashMap<String, u64> = HashMap::new();
                for e in &entries {
                    if !e.is_dir {
                        zip_file_sizes.insert(e.path.clone(), e.size);
                    }
                }
                let mut zip_dir_sizes: HashMap<String, u64> = HashMap::new();
                for (pfile, sz) in &zip_file_sizes {
                    let clean = pfile.trim_start_matches("./");
                    let mut acc = String::new();
                    for comp in clean.split('/') {
                        if comp.is_empty() { continue; }
                        if !acc.is_empty() { acc.push('/'); }
                        acc.push_str(comp);
                        zip_dir_sizes
                        .entry(format!("./{}/", acc))
                        .and_modify(|v| *v += *sz)
                        .or_insert(*sz);
                    }
                }

                // render inner tree
                let mut seen = BTreeSet::<String>::new();
                for z in &entries {
                    let mut e = z.path.trim_start_matches("./").to_string();
                    let is_dir = z.is_dir;
                    if is_dir { e.pop(); }
                    let parts: Vec<&str> = if e.is_empty() { vec![] } else { e.split('/').collect() };
                    let mut prefix = String::new();
                    for (i, part) in parts.iter().enumerate() {
                        if !prefix.is_empty() { prefix.push('/'); }
                        prefix.push_str(part);
                        if seen.insert(prefix.clone()) {
                            let is_last = i == parts.len() - 1;
                            let dir = !is_last || (is_last && is_dir);
                            let indent = " ".repeat((depth + 1 + i) * 4);
                            let full = if dir { format!("./{}/", prefix) } else { format!("./{}", prefix) };
                            let sz_show = if dir {
                                *zip_dir_sizes.get(&full).unwrap_or(&0)
                            } else {
                                z.size
                            };
                            let szs = colorize_size(&human_size(sz_show));
                            if dir {
                                lines.push(format!("{indent}{part}/  — {}", szs));
                            } else {
                                lines.push(format!("{indent}{part}  — {}", szs));
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(FullCache { lines, tar_sig: tar_sig.to_string(), included_zip_keys })
}

// -------------------- interactive remove picker --------------------

fn pick_members_for_removal(archive: &Path, ui: &UI, verbose: bool) -> Result<Vec<String>> {
    let (names, _zips, _sizes) = read_tar_entries(archive)?;
    let names_sorted = sort_paths_folder_first(&names)
    .into_iter()
    .filter(|p| !should_ignore_name(p))
    .collect::<Vec<_>>();

    vnote(verbose, ui, &format!("remove: loaded {} member(s) to pick from", names_sorted.len()));

    let display_list: Vec<String> = names_sorted
    .iter()
    .map(|s| s.trim_start_matches("./").to_string())
    .collect();

    let picks = ui.choose_multi(&display_list, "Select to delete:");
    let picks_norm: Vec<String> = picks
    .into_iter()
    .map(|s| if s.starts_with("./") { s } else { format!("./{s}") })
    .collect();

    Ok(picks_norm)
}

// -------------------- append/remove/extract --------------------

fn make_rel_path(p: &Path) -> Result<PathBuf> {
    let abs = fs::canonicalize(p)?;
    let cwd = std::env::current_dir()?;
    let rel = pathdiff::diff_paths(&abs, &cwd).unwrap_or_else(|| abs.file_name().unwrap().into());
    Ok(rel)
}

fn join_target(target: &str, rel: &Path) -> Result<PathBuf> {
    if target.is_empty() || target == "/" || target == "." {
        Ok(rel.to_path_buf())
    } else {
        Ok(Path::new(target).join(rel))
    }
}

fn append_one_file_with_pb(
    builder: &mut Builder<File>,
    src: &Path,
    dst_in_tar: &Path,
) -> Result<()> {
    // Prepare header
    let meta = fs::metadata(src)?;
    let size = meta.len();
    let mtime = meta.modified()?
    .duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

    let mut hdr = Header::new_gnu();
    hdr.set_path(dst_in_tar)?;
    hdr.set_size(size);
    hdr.set_mtime(mtime);
    hdr.set_mode(0o644);
    hdr.set_entry_type(EntryType::Regular);
    hdr.set_cksum();

    // Progress bar with MB/s
    let pb = ProgressBar::new(size);
    pb.set_style(
        ProgressStyle::with_template(
            "{spinner:.green} Importing [{bar:30.cyan/blue}] {bytes:>8}/{total_bytes:8}  @ {per_sec}"
        )
        .unwrap()
        .progress_chars("█▉▊▋▌▍▎▏ ")
    );

    let mut f = File::open(src)?;
    // Wrap reader so indicatif updates bytes & per_sec automatically
    let mut wrapped = pb.wrap_read(&mut f);
    builder.append_data(&mut hdr, dst_in_tar, &mut wrapped)?;
    pb.finish_and_clear();
    Ok(())
}

fn cmd_append(cli: &Cli) -> Result<()> {
    if cli.rest.is_empty() {
        bail!("--append requires path(s) to add");
    }
    let archive = &cli.archive;
    fs::create_dir_all(archive.parent().unwrap_or(Path::new(".")))?;
    let f = OpenOptions::new().create(true).append(true).read(true).open(archive)?;
    let mut b = Builder::new(f);
    let mut count = 0usize;

    for inpath in &cli.rest {
        if inpath.is_dir() {
            // Skip whole junk subtrees early using filter_entry
            let walker = WalkDir::new(inpath)
            .into_iter()
            .filter_entry(|e| !is_junk_component_os(e.file_name()));
            for entry in walker.filter_map(Result::ok) {
                let p = entry.path();

                // Skip obvious junk files specifically
                if is_junk_component_os(p.file_name().unwrap_or_else(|| OsStr::new(""))) {
                    continue;
                }
                if p.is_dir() {
                    continue;
                }

                let rel = make_rel_path(p)?;
                if should_ignore_name(&format!("./{}", rel.to_string_lossy())) {
                    continue;
                }

                let tar_path = join_target(cli.target_dir.as_deref().unwrap_or(""), &rel)?;
                append_one_file_with_pb(&mut b, p, &tar_path)?;
                count += 1;
            }
        } else if inpath.exists() {
            let rel = make_rel_path(inpath)?;
            if should_ignore_name(&format!("./{}", rel.to_string_lossy())) ||
                is_junk_component_os(inpath.file_name().unwrap_or_else(|| OsStr::new(""))) {
                    continue;
                }
                let tar_path = join_target(cli.target_dir.as_deref().unwrap_or(""), &rel)?;
                append_one_file_with_pb(&mut b, inpath, &tar_path)?;
                count += 1;
        } else {
            eprintln!("(skip missing) {}", inpath.display());
        }
    }
    b.finish()?;
    println!("{} Added {} item(s) under '{}'.",
             style("Done:").green().bold(),
             count,
             cli.target_dir.as_deref().unwrap_or("/")
    );

    // invalidate caches
    if let Ok(cp) = cache_paths(archive) {
        let _ = fs::remove_file(&cp.fast_txt);
        let _ = fs::remove_file(&cp.full_json);
        let _ = fs::remove_dir_all(&cp.zip_dir);
    }
    Ok(())
}

fn cmd_remove(cli: &Cli, _ui: &UI) -> Result<()> {
    if cli.rest.is_empty() {
        bail!("--remove requires paths to delete (tar members); none provided");
    }
    let archive = &cli.archive;
    let tmp = archive.with_extension("tmp.tar");

    let f_in = File::open(archive)?;
    let mut ar = Archive::new(f_in);
    let f_out = File::create(&tmp)?;
    let mut b = Builder::new(f_out);

    let remove_set: BTreeSet<String> = cli
    .rest
    .iter()
    .map(|p| {
        let mut s = p.to_string_lossy().to_string();
        if !s.starts_with("./") { s = format!("./{}", s); }
        s
    })
    .collect();

    for entry in ar.entries()? {
        let mut e = entry?;
        let path = e.path()?.to_string_lossy().into_owned();
        let mut norm = path.clone();
        if !norm.starts_with("./") { norm = format!("./{}", norm); }
        let skip = remove_set.iter().any(|r| {
            if r.ends_with('/') { norm.starts_with(r) } else { norm == *r }
        });
        if skip { continue; }

        let mut data = Vec::with_capacity(e.header().size().unwrap_or(0) as usize);
        e.read_to_end(&mut data)?;
        let mut hdr = Header::new_gnu();
        hdr.set_path(&path)?;
        hdr.set_size(data.len() as u64);
        hdr.set_cksum();
        if e.header().entry_type().is_dir() {
            hdr.set_entry_type(EntryType::Directory);
        } else {
            hdr.set_entry_type(EntryType::Regular);
        }
        b.append(&hdr, Cursor::new(data))?;
    }
    b.finish()?;
    fs::rename(&tmp, archive)?;

    // invalidate caches
    if let Ok(cp) = cache_paths(archive) {
        let _ = fs::remove_file(&cp.fast_txt);
        let _ = fs::remove_file(&cp.full_json);
        let _ = fs::remove_dir_all(&cp.zip_dir);
    }
    println!("{}", style("Removed selected item(s).").green());
    Ok(())
}

fn cmd_extract_zip(cli: &Cli, ui: &UI) -> Result<()> {
    let archive = &cli.archive;
    let member = cli
    .member
    .clone()
    .ok_or_else(|| anyhow!("--member <zip-path-in-tar> is required for --extract-zip"))?;
    let into = cli.into_dir.clone().unwrap_or(std::env::current_dir()?);

    // Get bytes for the specified ZIP member from the TAR
    let data = read_member_bytes(archive, &member)
    .with_context(|| format!("reading zip member bytes: {member}"))?;

    // Where to save the .zip extracted from the TAR
    let name = Path::new(&member).file_name().unwrap().to_string_lossy().to_string();
    let dest = into.join(name);

    if dest.exists() && !ui.confirm(&format!("Overwrite existing {}?", dest.display())) {
        bail!("aborted");
    }

    // Save the .zip (with MB/s progress)
    {
        let total = data.len() as u64;
        let pb = ui.progress_bytes(&format!("Saving {}", dest.file_name().unwrap().to_string_lossy()), total);
        let mut written = 0u64;
        let mut f = File::create(&dest)?;
        let mut pos = 0usize;
        let chunk = 64 * 1024;
        while pos < data.len() {
            let end = (pos + chunk).min(data.len());
            f.write_all(&data[pos..end])?;
            let inc = (end - pos) as u64;
            written += inc;
            pos = end;
            pb.set_position(written);
        }
        pb.finish_and_clear();
    }
    println!("{} {}", style("Saved →").bold(), dest.display());

    // Optional: extract contents (flag or prompt)
    let do_extract_contents = cli.extract_zip_contents || ui.confirm("Do you also want to extract the contents of this ZIP now?");
    if do_extract_contents {
        let file = File::open(&dest)?;
        let mut zr = zip::ZipArchive::new(file)?;
        let total_files = zr.len() as u64;

        for i in 0..zr.len() {
            let mut zf = zr.by_index(i)?;
            // Sanitize path
            let out_rel = zf.mangled_name();
            let out_path = into.join(&out_rel);

            // Skip junk in extracted content
            if let Some(s) = out_rel.to_str() {
                if should_ignore_name(s) {
                    continue;
                }
            }

            if zf.is_dir() {
                fs::create_dir_all(&out_path)?;
            } else {
                if let Some(parent) = out_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let size = zf.size();
                let pb = ui.progress_bytes(
                    &format!("Extracting {}", out_rel.file_name().and_then(|s| s.to_str()).unwrap_or("-")),
                                           size
                );

                // Manual copy to report MB/s + bytes
                let mut out_f = File::create(&out_path)?;
                let mut buf = [0u8; 64 * 1024];
                let mut copied = 0u64;
                loop {
                    let n = zf.read(&mut buf)?;
                    if n == 0 { break; }
                    out_f.write_all(&buf[..n])?;
                    copied += n as u64;
                    pb.set_position(copied);
                }
                pb.finish_and_clear();
            }

            // optional: small overall progress line (no bar), to echo progress through files
            let idx = i + 1;
            let msg = format!("({}/{})", idx, total_files);
            println!(" {}", style(msg).dim());
        }
        println!("{} {}", style("Extracted ZIP contents into").bold(), into.display());
    }

    Ok(())
}

// -------------------- main --------------------

fn main() -> Result<()> {
    let mut cli = Cli::parse();
    let ui = UI::new(cli.yes);

    // default mode = append
    if !(cli.list || cli.list_all || cli.append || cli.remove || cli.extract_zip) {
        cli.append = true;
    }
    if [cli.list, cli.list_all, cli.append, cli.remove, cli.extract_zip]
        .into_iter().filter(|b| *b).count() > 1 {
            bail!("Pick one mode only.");
        }
        let archive = &cli.archive;
    if !archive.exists() {
        bail!("Archive not found: {}", archive.display());
    }

    let cache = cache_paths(archive)?;
    let (mt, sz) = file_mtime_size(archive)?;
    let tar_sig = format!("{}|{}|{}", archive.display(), mt, sz);

    if cli.list || cli.list_all {
        vnote(cli.verbose, &ui, &format!("list: expand_zip={} archive={} prepass={}",
                                         cli.list_all, archive.display(), cli.prepass));

        if cli.list_all {
            if let Some(fc) = read_full_cache(&cache) {
                if fc.tar_sig == tar_sig {
                    vnote(cli.verbose, &ui, &format!("list: using cache {}", cache.full_json.display()));
                    ui.box_lines(&fc.lines);
                    return Ok(());
                }
            }
        } else if let Some(lines) = read_fast_cache(&cache) {
            vnote(cli.verbose, &ui, &format!("list: using cache {}", cache.fast_txt.display()));
            ui.box_lines(&lines);
            return Ok(());
        }

        let (names, zips, file_sizes) = if cli.prepass {
            ui.spinner("Reading archive entries…", || read_tar_entries(archive)).unwrap()
        } else {
            read_tar_entries(archive)?
        };
        let names_sorted = sort_paths_folder_first(&names);
        let dir_sizes = accumulate_dir_sizes(&names_sorted, &file_sizes);

        if cli.list_all {
            let fc = build_list_all(archive, &names_sorted, &zips, &file_sizes, &cache, &tar_sig, &ui, cli.verbose)?;
            ui.box_lines(&fc.lines);
            let _ = write_full_cache(&cache, &fc);
        } else {
            let base_tree = render_tree_with_sizes(&names_sorted, &file_sizes, &dir_sizes);
            ui.box_lines(&base_tree);
            let _ = write_fast_cache(&cache, &base_tree);
        }
        return Ok(());
    }

    if cli.append {
        return cmd_append(&cli);
    }

    if cli.remove {
        // interactive picker when no paths are provided and not forced yes
        if cli.rest.is_empty() && !cli.yes {
            let picks = pick_members_for_removal(&cli.archive, &ui, cli.verbose)?;
            if picks.is_empty() {
                bail!("Nothing selected.");
            }
            let cli2 = Cli { rest: picks.into_iter().map(PathBuf::from).collect(), ..cli };
            return cmd_remove(&cli2, &ui);
        }
        return cmd_remove(&cli, &ui);
    }

    if cli.extract_zip {
        return cmd_extract_zip(&cli, &ui);
    }

    Ok(())
}
