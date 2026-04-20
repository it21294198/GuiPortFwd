//! GuiPortFwd — GUI port forwarder (Windows, macOS, Linux)
//! Built with egui/eframe (native, no browser needed)

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use eframe::egui::{self, Color32, FontId, RichText, Stroke, Vec2};
use std::net::{IpAddr, SocketAddr};
use std::process::Command;
use std::sync::{Arc, Mutex};
use tokio::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

// ─── Data types ───────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct Rule {
    listen_port: u16,
    target_host: String,
    target_port: u16,
}

#[derive(Clone, Debug, PartialEq)]
enum RuleStatus {
    Running,
    Idle,
    Error(String),
}

struct ActiveRule {
    rule:        Rule,
    status:      RuleStatus,
    stop_tx:     Option<oneshot::Sender<()>>,
    connections: u64,
    /// On macOS/Linux we also spawn a socat child process; keep its handle
    /// so we can kill it when the rule is stopped.
    #[cfg(unix)]
    socat_child: Option<std::process::Child>,
}

// ─── Firewall ─────────────────────────────────────────────────────────────────

/// Add a firewall rule to allow inbound TCP on `port`.
/// Each platform uses its native mechanism.
fn fw_add(port: u16) -> bool {
    #[cfg(windows)]
    {
        // Windows: netsh advfirewall
        Command::new("netsh")
            .args([
                "advfirewall", "firewall", "add", "rule",
                &format!("name=GuiPortFwd-{}", port),
                "dir=in", "action=allow", "protocol=TCP",
                &format!("localport={}", port),
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[cfg(target_os = "macos")]
    {
        // macOS: add a pf pass rule via pfctl (requires sudo / root)
        let rule = format!("pass in proto tcp from any to any port {}\n", port);
        let result = Command::new("sh")
            .args(["-c", &format!("echo '{}' | sudo pfctl -ef - 2>/dev/null", rule.trim())])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        result
    }

    #[cfg(target_os = "linux")]
    {
        // Linux: iptables (tries direct first, falls back to sudo)
        let args = [
            "iptables", "-I", "INPUT", "-p", "tcp",
            "--dport", &port.to_string(), "-j", "ACCEPT",
        ];
        let ok = Command::new(args[0]).args(&args[1..])
            .output().map(|o| o.status.success()).unwrap_or(false);
        if ok { return true; }
        Command::new("sudo").args(args)
            .output().map(|o| o.status.success()).unwrap_or(false)
    }

    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    { let _ = port; false }
}

/// Remove the firewall rule previously added for `port`.
fn fw_remove(port: u16) {
    #[cfg(windows)]
    {
        let _ = Command::new("netsh")
            .args([
                "advfirewall", "firewall", "delete", "rule",
                &format!("name=GuiPortFwd-{}", port),
            ])
            .output();
    }

    #[cfg(target_os = "macos")]
    {
        // Flush pf rules (best-effort; may affect other rules — acceptable for dev use)
        let _ = Command::new("sudo").args(["pfctl", "-F", "rules"]).output();
        let _ = port;
    }

    #[cfg(target_os = "linux")]
    {
        let args = [
            "iptables", "-D", "INPUT", "-p", "tcp",
            "--dport", &port.to_string(), "-j", "ACCEPT",
        ];
        let ok = Command::new(args[0]).args(&args[1..])
            .output().map(|o| o.status.success()).unwrap_or(false);
        if !ok {
            let _ = Command::new("sudo").args(args).output();
        }
    }

    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    { let _ = port; }
}

// ─── socat helper (macOS / Linux only) ───────────────────────────────────────
//
// On Unix we can optionally hand off forwarding to socat, which is the
// idiomatic tool on those platforms.  This spawns:
//   socat TCP-LISTEN:<listen>,reuseaddr,fork TCP:<host>:<port>
// as a child process and returns its handle so the caller can kill it later.
//
// If socat is not installed the Rust async forwarder is used instead —
// the two paths are functionally identical.

#[cfg(unix)]
fn try_spawn_socat(listen_port: u16, target_host: &str, target_port: u16)
    -> Option<std::process::Child>
{
    Command::new("socat")
        .arg(format!("TCP-LISTEN:{},reuseaddr,fork", listen_port))
        .arg(format!("TCP:{}:{}", target_host, target_port))
        .spawn()
        .ok()
}

// ─── Admin / privilege check ──────────────────────────────────────────────────

fn is_elevated() -> bool {
    #[cfg(windows)]
    { Command::new("net").args(["session"]).output().map(|o| o.status.success()).unwrap_or(false) }

    #[cfg(unix)]
    { unsafe { libc::geteuid() == 0 } }

    #[cfg(not(any(windows, unix)))]
    { false }
}

// ─── LAN IP detection ─────────────────────────────────────────────────────────

fn lan_ip() -> Option<IpAddr> {
    #[cfg(windows)]
    {
        // ipconfig — find first non-loopback IPv4 line
        let out = Command::new("ipconfig").output().ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let t = line.trim();
            if !t.contains("IPv4") { continue; }
            if let Some(pos) = t.rfind(':') {
                let ip_str = t[pos + 1..].trim();
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    if !ip.is_loopback() { return Some(ip); }
                }
            }
        }
        None
    }

    #[cfg(target_os = "macos")]
    {
        // Strategy 1: ipconfig getifaddr <iface> — fast, reliable, one IP per interface
        for iface in &["en0", "en1", "en2", "en3"] {
            if let Ok(out) = Command::new("ipconfig").args(["getifaddr", iface]).output() {
                let ip_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    if !ip.is_loopback() { return Some(ip); }
                }
            }
        }
        // Strategy 2: scan all interfaces via ifconfig -a
        if let Ok(out) = Command::new("ifconfig").arg("-a").output() {
            let text = String::from_utf8_lossy(&out.stdout);
            for line in text.lines() {
                let t = line.trim();
                if !t.starts_with("inet ") || t.starts_with("inet6") { continue; }
                let parts: Vec<&str> = t.split_whitespace().collect();
                if let Some(ip_str) = parts.get(1) {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        if !ip.is_loopback() { return Some(ip); }
                    }
                }
            }
        }
        None
    }

    #[cfg(target_os = "linux")]
    {
        // ip addr show — first non-loopback inet
        let out = Command::new("ip").args(["addr", "show"]).output().ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let t = line.trim();
            if t.starts_with("inet ") && !t.starts_with("inet6") {
                let parts: Vec<&str> = t.split_whitespace().collect();
                if let Some(cidr) = parts.get(1) {
                    let ip_str = cidr.split('/').next().unwrap_or("");
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        if !ip.is_loopback() { return Some(ip); }
                    }
                }
            }
        }
        None
    }

    #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
    { None }
}

// ─── Async TCP forwarder (Rust fallback — used on Windows always,
//     on macOS/Linux when socat is not available) ───────────────────────────────

async fn forward_conn(mut client: TcpStream, target: Arc<String>) -> io::Result<()> {
    let mut server = TcpStream::connect(target.as_str()).await?;
    client.set_nodelay(true)?;
    server.set_nodelay(true)?;
    let (mut cr, mut cw) = client.split();
    let (mut sr, mut sw) = server.split();
    tokio::select! {
        r = io::copy(&mut cr, &mut sw) => { r?; }
        r = io::copy(&mut sr, &mut cw) => { r?; }
    }
    Ok(())
}

fn spawn_rust_forwarder(
    rule:       Rule,
    conn_count: Arc<Mutex<u64>>,
    status_out: Arc<Mutex<RuleStatus>>,
) -> oneshot::Sender<()> {
    let (stop_tx, stop_rx) = oneshot::channel::<()>();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            let addr: SocketAddr = format!("0.0.0.0:{}", rule.listen_port).parse().unwrap();
            let listener = match TcpListener::bind(addr).await {
                Ok(l)  => { *status_out.lock().unwrap() = RuleStatus::Running; l }
                Err(e) => { *status_out.lock().unwrap() = RuleStatus::Error(e.to_string()); return; }
            };
            let target = Arc::new(format!("{}:{}", rule.target_host, rule.target_port));
            let mut stop_rx = stop_rx;
            loop {
                tokio::select! {
                    _ = &mut stop_rx => break,
                    res = listener.accept() => {
                        match res {
                            Ok((stream, _)) => {
                                let t  = target.clone();
                                let cc = conn_count.clone();
                                tokio::spawn(async move {
                                    *cc.lock().unwrap() += 1;
                                    let _ = forward_conn(stream, t).await;
                                });
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
            *status_out.lock().unwrap() = RuleStatus::Idle;
        });
    });
    stop_tx
}

// ─── App state ────────────────────────────────────────────────────────────────

struct PortFwdApp {
    listen_port: String,
    target_host: String,
    target_port: String,
    rules:       Vec<ActiveRule>,
    rule_status: Vec<Arc<Mutex<RuleStatus>>>,
    rule_conns:  Vec<Arc<Mutex<u64>>>,
    lan_ip:      String,
    is_admin:    bool,
    log:         Vec<String>,
}

impl Default for PortFwdApp {
    fn default() -> Self {
        let lan = lan_ip().map(|i| i.to_string()).unwrap_or_else(|| "unknown".to_string());
        let log_msg = if lan == "unknown" {
            "⚠  Could not detect LAN IP — is network connected?".to_string()
        } else {
            format!("✓  LAN IP: {}  — use this address on your phone.", lan)
        };

        // Hint about how to get firewall auto-management on each platform
        #[cfg(windows)]
        let priv_hint = "ℹ  Firewall rules require running as Administrator.";
        #[cfg(target_os = "macos")]
        let priv_hint = "ℹ  Firewall rules require sudo. socat used for forwarding if available.";
        #[cfg(target_os = "linux")]
        let priv_hint = "ℹ  Firewall rules require sudo (iptables). socat used if available.";
        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        let priv_hint = "ℹ  Firewall rule management not supported on this platform.";

        Self {
            listen_port: "9000".to_string(),
            target_host: "127.0.0.1".to_string(),
            target_port: "8080".to_string(),
            rules:       vec![],
            rule_status: vec![],
            rule_conns:  vec![],
            lan_ip:      lan,
            is_admin:    is_elevated(),
            log:         vec!["GuiPortFwd ready.".to_string(), log_msg, priv_hint.to_string()],
        }
    }
}

impl PortFwdApp {
    fn add_log(&mut self, msg: impl Into<String>) {
        let m = msg.into();
        if self.log.len() > 200 { self.log.remove(0); }
        self.log.push(m);
    }

    fn start_rule(&mut self) {
        let lp: u16 = match self.listen_port.trim().parse() {
            Ok(p)  => p,
            Err(_) => { self.add_log("✗ Invalid listen port"); return; }
        };
        let tp: u16 = match self.target_port.trim().parse() {
            Ok(p)  => p,
            Err(_) => { self.add_log("✗ Invalid target port"); return; }
        };
        let th = self.target_host.trim().to_string();
        if th.is_empty() { self.add_log("✗ Target host is empty"); return; }

        if lp == tp && (th == "127.0.0.1" || th == "localhost") {
            self.add_log("✗ Listen and target port are the same on localhost — would loop.");
            return;
        }
        if self.rules.iter().any(|r| r.rule.listen_port == lp && r.status == RuleStatus::Running) {
            self.add_log(format!("✗ Port {} is already forwarding", lp));
            return;
        }

        let rule = Rule { listen_port: lp, target_host: th.clone(), target_port: tp };

        // ── Firewall rule ─────────────────────────────────────────────────────
        if self.is_admin {
            if fw_add(lp) {
                self.add_log(format!("✓  Firewall: opened port {}", lp));
            } else {
                self.add_log(format!("⚠  Firewall: could not open port {} — open manually if needed", lp));
            }
        }

        // ── Forwarder: try socat on Unix, fall back to Rust async ─────────────
        let status = Arc::new(Mutex::new(RuleStatus::Idle));
        let conns  = Arc::new(Mutex::new(0u64));

        #[cfg(unix)]
        let socat_child = try_spawn_socat(lp, &th, tp);

        #[cfg(unix)]
        let used_socat = socat_child.is_some();
        #[cfg(not(unix))]
        let used_socat = false;

        // Always start the Rust forwarder as well on Windows;
        // on Unix start it only if socat wasn't available.
        let stop_tx = if !used_socat {
            let tx = spawn_rust_forwarder(rule.clone(), conns.clone(), status.clone());
            Some(tx)
        } else {
            // socat owns the port — mark status Running immediately
            *status.lock().unwrap() = RuleStatus::Running;
            None
        };

        let engine = if used_socat { "socat" } else { "built-in" };
        self.add_log(format!("▶  0.0.0.0:{} → {}:{}  ({})", lp, th, tp, engine));

        self.rules.push(ActiveRule {
            rule,
            status: RuleStatus::Running,
            stop_tx,
            connections: 0,
            #[cfg(unix)]
            socat_child,
        });
        self.rule_status.push(status);
        self.rule_conns.push(conns);
    }

    fn stop_rule(&mut self, idx: usize) {
        // Stop Rust forwarder
        if let Some(tx) = self.rules[idx].stop_tx.take() { let _ = tx.send(()); }

        // Kill socat child if present
        #[cfg(unix)]
        if let Some(mut child) = self.rules[idx].socat_child.take() {
            let _ = child.kill();
        }

        fw_remove(self.rules[idx].rule.listen_port);
        let lp = self.rules[idx].rule.listen_port;
        self.add_log(format!("■  stopped :{}", lp));
        self.rules.remove(idx);
        self.rule_status.remove(idx);
        self.rule_conns.remove(idx);
    }

    fn sync_statuses(&mut self) {
        for (i, r) in self.rules.iter_mut().enumerate() {
            r.status      = self.rule_status[i].lock().unwrap().clone();
            r.connections = *self.rule_conns[i].lock().unwrap();
        }
    }
}

// ─── UI ───────────────────────────────────────────────────────────────────────

impl eframe::App for PortFwdApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.sync_statuses();
        ctx.request_repaint_after(std::time::Duration::from_millis(500));

        let bg      = Color32::from_rgb(15, 17, 23);
        let surface = Color32::from_rgb(22, 26, 35);
        let card    = Color32::from_rgb(28, 33, 45);
        let border  = Color32::from_rgb(45, 52, 68);
        let accent  = Color32::from_rgb(82, 160, 255);
        let green   = Color32::from_rgb(52, 211, 153);
        let red     = Color32::from_rgb(251, 113, 133);
        let amber   = Color32::from_rgb(251, 191, 36);
        let txt     = Color32::from_rgb(220, 228, 240);
        let txt_dim = Color32::from_rgb(100, 115, 140);

        let mut vis = egui::Visuals::dark();
        vis.window_fill                      = bg;
        vis.panel_fill                       = bg;
        vis.widgets.noninteractive.bg_fill   = surface;
        vis.widgets.inactive.bg_fill         = card;
        vis.widgets.hovered.bg_fill          = Color32::from_rgb(38, 45, 62);
        vis.widgets.active.bg_fill           = Color32::from_rgb(50, 60, 82);
        vis.widgets.noninteractive.fg_stroke = Stroke::new(1.0, border);
        vis.widgets.inactive.fg_stroke       = Stroke::new(1.0, border);
        vis.widgets.hovered.fg_stroke        = Stroke::new(1.5, accent);
        vis.selection.bg_fill                = Color32::from_rgba_premultiplied(82, 160, 255, 60);
        ctx.set_visuals(vis);

        #[cfg(windows)]
        let admin_warn = "⚠  Run as Administrator to enable automatic firewall rules.";
        #[cfg(target_os = "macos")]
        let admin_warn = "⚠  Run with sudo to enable automatic firewall rules.";
        #[cfg(target_os = "linux")]
        let admin_warn = "⚠  Run with sudo to enable automatic iptables rules.";
        #[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
        let admin_warn = "⚠  Elevated privileges needed for automatic firewall rules.";

        egui::CentralPanel::default()
            .frame(egui::Frame::none().fill(bg).inner_margin(egui::Margin::same(0.0)))
            .show(ctx, |ui| {

            // ── Header ────────────────────────────────────────────────────────
            egui::Frame::none()
                .fill(surface)
                .stroke(Stroke::new(1.0, border))
                .inner_margin(egui::Margin { left: 20.0, right: 20.0, top: 14.0, bottom: 14.0 })
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("⟳").font(FontId::proportional(22.0)).color(accent));
                        ui.add_space(6.0);
                        ui.label(RichText::new("GuiPortFwd").font(FontId::proportional(18.0)).color(txt).strong());
                        ui.label(RichText::new("  LAN Port Forwarder").font(FontId::proportional(13.0)).color(txt_dim));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            let (bg_col, label, fg_col) = if self.is_admin {
                                (Color32::from_rgba_premultiplied(52, 211, 153, 30), "● Admin", green)
                            } else {
                                (Color32::from_rgba_premultiplied(251, 113, 133, 30), "● No Admin", red)
                            };
                            egui::Frame::none().fill(bg_col)
                                .rounding(egui::Rounding::same(4.0))
                                .inner_margin(egui::Margin { left: 8.0, right: 8.0, top: 3.0, bottom: 3.0 })
                                .show(ui, |ui| {
                                    ui.label(RichText::new(label).font(FontId::proportional(11.0)).color(fg_col));
                                });
                            ui.add_space(12.0);
                            ui.label(RichText::new(format!("PC LAN IP  {}", self.lan_ip))
                                .font(FontId::monospace(12.0)).color(txt_dim));
                        });
                    });
                });

            egui::ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
                ui.add_space(16.0);

                // ── New rule form ─────────────────────────────────────────────
                egui::Frame::none()
                    .fill(card)
                    .rounding(egui::Rounding::same(10.0))
                    .stroke(Stroke::new(1.0, border))
                    .inner_margin(egui::Margin::same(16.0))
                    .outer_margin(egui::Margin { left: 16.0, right: 16.0, top: 0.0, bottom: 12.0 })
                    .show(ui, |ui| {
                        ui.label(RichText::new("New forwarding rule").font(FontId::proportional(13.0)).color(txt_dim));
                        ui.add_space(10.0);
                        ui.horizontal(|ui| {
                            ui.vertical(|ui| {
                                ui.label(RichText::new("Listen port").font(FontId::proportional(11.0)).color(txt_dim));
                                let r = ui.add(egui::TextEdit::singleline(&mut self.listen_port)
                                    .font(FontId::monospace(15.0)).desired_width(90.0).hint_text("9000"));
                                if r.changed() { self.listen_port.retain(|c| c.is_ascii_digit()); }
                            });
                            ui.add_space(8.0);
                            ui.label(RichText::new("→").font(FontId::proportional(20.0)).color(accent));
                            ui.add_space(8.0);
                            ui.vertical(|ui| {
                                ui.label(RichText::new("Target host").font(FontId::proportional(11.0)).color(txt_dim));
                                ui.add(egui::TextEdit::singleline(&mut self.target_host)
                                    .font(FontId::monospace(15.0)).desired_width(150.0).hint_text("127.0.0.1"));
                            });
                            ui.add_space(6.0);
                            ui.label(RichText::new(":").font(FontId::proportional(20.0)).color(txt_dim));
                            ui.add_space(2.0);
                            ui.vertical(|ui| {
                                ui.label(RichText::new("Target port").font(FontId::proportional(11.0)).color(txt_dim));
                                let r = ui.add(egui::TextEdit::singleline(&mut self.target_port)
                                    .font(FontId::monospace(15.0)).desired_width(90.0).hint_text("8080"));
                                if r.changed() { self.target_port.retain(|c| c.is_ascii_digit()); }
                            });
                            ui.add_space(12.0);
                            ui.vertical(|ui| {
                                ui.add_space(16.0);
                                if ui.add(egui::Button::new(
                                    RichText::new("▶  Start").font(FontId::proportional(13.0)).color(Color32::WHITE))
                                    .fill(accent)
                                    .rounding(egui::Rounding::same(6.0))
                                    .min_size(Vec2::new(100.0, 32.0))
                                ).clicked() { self.start_rule(); }
                            });
                        });

                        if !self.is_admin {
                            ui.add_space(8.0);
                            egui::Frame::none()
                                .fill(Color32::from_rgba_premultiplied(251, 191, 36, 20))
                                .rounding(egui::Rounding::same(6.0))
                                .inner_margin(egui::Margin { left: 10.0, right: 10.0, top: 6.0, bottom: 6.0 })
                                .show(ui, |ui| {
                                    ui.label(RichText::new(admin_warn)
                                        .font(FontId::proportional(11.5)).color(amber));
                                });
                        }
                    });

                // ── Active rules ──────────────────────────────────────────────
                if !self.rules.is_empty() {
                    ui.label(RichText::new("  Active rules").font(FontId::proportional(11.0)).color(txt_dim));
                    ui.add_space(6.0);
                    let mut to_stop: Option<usize> = None;

                    for (i, rule) in self.rules.iter().enumerate() {
                        let (dot_col, status_txt) = match &rule.status {
                            RuleStatus::Running  => (green,   "running"),
                            RuleStatus::Idle     => (txt_dim, "idle"),
                            RuleStatus::Error(e) => (red,     e.as_str()),
                        };
                        let connect_url = format!("http://{}:{}", self.lan_ip, rule.rule.listen_port);

                        egui::Frame::none()
                            .fill(surface)
                            .rounding(egui::Rounding::same(8.0))
                            .stroke(Stroke::new(1.0, border))
                            .inner_margin(egui::Margin { left: 14.0, right: 14.0, top: 10.0, bottom: 12.0 })
                            .outer_margin(egui::Margin { left: 16.0, right: 16.0, top: 0.0, bottom: 8.0 })
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new("●").font(FontId::proportional(10.0)).color(dot_col));
                                    ui.add_space(4.0);
                                    ui.label(RichText::new(format!(
                                        "0.0.0.0:{} → {}:{}",
                                        rule.rule.listen_port, rule.rule.target_host, rule.rule.target_port,
                                    )).font(FontId::monospace(13.0)).color(txt));
                                    ui.add_space(10.0);
                                    ui.label(RichText::new(status_txt).font(FontId::proportional(11.0)).color(dot_col));
                                    ui.add_space(10.0);
                                    ui.label(RichText::new(format!("{} conn", rule.connections))
                                        .font(FontId::proportional(11.0)).color(txt_dim));
                                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                        if ui.add(egui::Button::new(
                                            RichText::new("■  Stop").font(FontId::proportional(12.0)).color(Color32::WHITE))
                                            .fill(Color32::from_rgb(180, 50, 70))
                                            .rounding(egui::Rounding::same(5.0))
                                            .min_size(Vec2::new(80.0, 26.0))
                                        ).clicked() { to_stop = Some(i); }
                                    });
                                });
                                ui.add_space(8.0);
                                egui::Frame::none()
                                    .fill(Color32::from_rgb(10, 12, 18))
                                    .rounding(egui::Rounding::same(6.0))
                                    .inner_margin(egui::Margin { left: 10.0, right: 10.0, top: 6.0, bottom: 6.0 })
                                    .show(ui, |ui| {
                                        ui.horizontal(|ui| {
                                            ui.label(RichText::new("Open on phone:")
                                                .font(FontId::proportional(11.0)).color(txt_dim));
                                            ui.add_space(6.0);
                                            ui.label(RichText::new(&connect_url)
                                                .font(FontId::monospace(14.0)).color(accent));
                                            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                                                if ui.add(egui::Button::new(
                                                    RichText::new("Copy").font(FontId::proportional(11.0)).color(txt_dim))
                                                    .fill(Color32::TRANSPARENT)
                                                    .stroke(Stroke::new(0.5, border))
                                                    .rounding(egui::Rounding::same(4.0))
                                                    .min_size(Vec2::new(44.0, 22.0))
                                                ).clicked() {
                                                    ui.output_mut(|o| o.copied_text = connect_url.clone());
                                                }
                                            });
                                        });
                                    });
                            });
                    }
                    if let Some(idx) = to_stop { self.stop_rule(idx); }
                    ui.add_space(4.0);
                }

                // ── Log ───────────────────────────────────────────────────────
                ui.label(RichText::new("  Log").font(FontId::proportional(11.0)).color(txt_dim));
                ui.add_space(4.0);
                egui::Frame::none()
                    .fill(Color32::from_rgb(10, 12, 18))
                    .rounding(egui::Rounding::same(8.0))
                    .stroke(Stroke::new(1.0, border))
                    .inner_margin(egui::Margin::same(12.0))
                    .outer_margin(egui::Margin { left: 16.0, right: 16.0, top: 0.0, bottom: 16.0 })
                    .show(ui, |ui| {
                        egui::ScrollArea::vertical()
                            .id_source("log")
                            .max_height(140.0)
                            .stick_to_bottom(true)
                            .show(ui, |ui| {
                                for line in &self.log {
                                    ui.label(RichText::new(line)
                                        .font(FontId::monospace(12.0)).color(txt_dim));
                                }
                            });
                    });
            });
        });
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        for rule in &mut self.rules {
            if let Some(tx) = rule.stop_tx.take() { let _ = tx.send(()); }
            #[cfg(unix)]
            if let Some(mut child) = rule.socat_child.take() { let _ = child.kill(); }
            fw_remove(rule.rule.listen_port);
        }
    }
}

// ─── Entry point ──────────────────────────────────────────────────────────────

fn main() -> eframe::Result<()> {
    eframe::run_native(
        "GuiPortFwd",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_title("GuiPortFwd")
                .with_inner_size([660.0, 500.0])
                .with_min_inner_size([540.0, 360.0])
                .with_resizable(true),
            ..Default::default()
        },
        Box::new(|_cc| Ok(Box::new(PortFwdApp::default()))),
    )
}