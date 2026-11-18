//! "Lưu trữ & Sao lưu" settings tab, scheduled backups and backup-before-exit (ADR-0004).
//!
//! The UI never touches the bucket, SQLite or `archive.json` itself: it edits a copy of the
//! config and sends `WorkerCmd::Archive*` commands (INV-3).

use super::archive_worker::BackupReason;
use super::*;
use crate::archive::config::{ArchiveConfig, Provider, Retention};
use crate::archive::engine::BackupReport;

/// How long quitting waits for the backup-before-exit.
const EXIT_BACKUP_LIMIT: Duration = Duration::from_secs(10);
/// Minimum gap between scheduled attempts (also after a failure).
const SCHEDULE_RETRY: Duration = Duration::from_secs(10 * 60);

/// Label column width for the bucket/encryption forms.
const TARGET_LABEL_W: f32 = 120.0;
/// Label column width for the backup/retention forms.
const RETENTION_LABEL_W: f32 = 140.0;

/// One form row: a fixed-width, vertically centred label, then `add(ui, remaining_width)`.
/// Keeps inputs aligned in a column without `egui::Grid`, whose cells size to content.
fn field_row(
    ui: &mut egui::Ui,
    pal: &ThemePalette,
    label: &str,
    label_w: f32,
    add: impl FnOnce(&mut egui::Ui, f32),
) {
    let h = ui.spacing().interact_size.y;
    ui.horizontal(|ui| {
        ui.allocate_ui_with_layout(
            Vec2::new(label_w, h),
            Layout::left_to_right(Align::Center),
            |ui| {
                ui.set_min_size(Vec2::new(label_w, h));
                ui.add(
                    egui::Label::new(RichText::new(label).color(pal.text_primary).size(13.0))
                        .truncate(),
                );
            },
        );
        let w = (ui.available_width() - 2.0).max(80.0);
        add(ui, w);
    });
}

#[derive(Default)]
pub(crate) struct ArchiveUi {
    /// Copy being edited in the form.
    form: ArchiveConfig,
    /// Last config confirmed by the worker; drives the schedule.
    saved: Option<ArchiveConfig>,
    requested: bool,
    passphrase: String,
    show_secret: bool,
    busy: Option<&'static str>,
    status: Option<(bool, String)>,
    last_report: Option<BackupReport>,
    last_schedule_attempt: Option<std::time::Instant>,
    exit_started: Option<std::time::Instant>,
    exit_ready: bool,
}

fn provider_label(p: Provider) -> &'static str {
    match p {
        Provider::S3 => "Amazon S3",
        Provider::R2 => "Cloudflare R2",
        Provider::Gcs => "Google Cloud Storage",
        Provider::Minio => "MinIO",
        Provider::Custom => "Khác (tương thích S3)",
    }
}

fn format_time(ms: i64) -> String {
    chrono::DateTime::from_timestamp_millis(ms)
        .map(|t| {
            t.with_timezone(&chrono::Local)
                .format("%H:%M %d/%m/%Y")
                .to_string()
        })
        .unwrap_or_else(|| "—".into())
}

fn describe_report(r: &BackupReport) -> String {
    let mut parts = vec![format!("{} tin ({} segment)", r.rows, r.segments)];
    if r.media_files > 0 {
        parts.push(format!(
            "{} tệp media ({:.1} MB)",
            r.media_files,
            r.media_bytes as f64 / 1_048_576.0
        ));
    }
    if r.media_skipped > 0 {
        parts.push(format!("bỏ qua {} tệp > 256 MB", r.media_skipped));
    }
    if r.pruned_rows > 0 || r.pruned_media > 0 {
        parts.push(format!(
            "dọn {} tin, {} tệp ở máy",
            r.pruned_rows, r.pruned_media
        ));
    }
    parts.join(", ")
}

impl ZaloGuiApp {
    fn archive_send(&self, cmd: WorkerCmd) {
        if let Some(tx) = WORKER_TX.get() {
            let _ = tx.send(cmd);
        }
    }

    fn open_thread_ids(&self) -> Vec<String> {
        self.threads
            .get(self.selected_thread_index)
            .map(|t| vec![t.id.clone()])
            .unwrap_or_default()
    }

    /// Whether unattended backups can run: enabled, and a key is available when encrypting.
    fn archive_can_run_unattended(&self) -> bool {
        self.archive_ui
            .saved
            .as_ref()
            .is_some_and(|c| c.enabled && (!c.encrypt || c.master_key.is_some()))
            && self.is_logged_in
            && !self.user_uin.is_empty()
    }

    /// Per-frame bookkeeping: load the config once, fire scheduled backups, finish a
    /// backup-before-exit that ran out of time.
    pub(super) fn archive_tick(&mut self, ctx: &egui::Context) {
        if !self.archive_ui.requested && WORKER_TX.get().is_some() {
            self.archive_ui.requested = true;
            self.archive_send(WorkerCmd::ArchiveLoadConfig);
        }
        if let Some(started) = self.archive_ui.exit_started {
            if started.elapsed() >= EXIT_BACKUP_LIMIT && !self.archive_ui.exit_ready {
                self.archive_ui.exit_ready = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            }
            ctx.request_repaint_after(Duration::from_millis(250));
            return;
        }
        if self.archive_ui.busy.is_some() || !self.archive_can_run_unattended() {
            return;
        }
        let Some(cfg) = self.archive_ui.saved.as_ref() else {
            return;
        };
        if cfg.auto_backup_hours == 0 {
            return;
        }
        if self
            .archive_ui
            .last_schedule_attempt
            .is_some_and(|t| t.elapsed() < SCHEDULE_RETRY)
        {
            return;
        }
        let last = cfg.last_backup_ms.get(&self.user_uin).copied().unwrap_or(0);
        let due = last + i64::from(cfg.auto_backup_hours) * 3_600_000;
        if chrono::Utc::now().timestamp_millis() >= due {
            self.archive_ui.last_schedule_attempt = Some(std::time::Instant::now());
            self.archive_ui.busy = Some("Đang sao lưu tự động…");
            let keep = self.open_thread_ids();
            self.archive_send(WorkerCmd::ArchiveBackup {
                reason: BackupReason::Scheduled,
                keep_threads: keep,
            });
        }
    }

    /// Called when the window is asked to close. Returns `true` when closing is postponed
    /// for a final backup (at most [`EXIT_BACKUP_LIMIT`]).
    pub(super) fn archive_defer_close(&mut self, ctx: &egui::Context) -> bool {
        if self.archive_ui.exit_ready {
            return false;
        }
        if self.archive_ui.exit_started.is_some() {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            return true;
        }
        if !self.archive_can_run_unattended() {
            return false;
        }
        self.archive_ui.exit_started = Some(std::time::Instant::now());
        let keep = self.open_thread_ids();
        self.archive_send(WorkerCmd::ArchiveBackup {
            reason: BackupReason::BeforeExit,
            keep_threads: keep,
        });
        ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        // Quitting was asked for: hide the window now, finish the backup in the background.
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        self.show_toast("⏳ Đang sao lưu trước khi thoát (tối đa 10 giây)…");
        true
    }

    pub(super) fn archive_on_config(
        &mut self,
        result: Result<ArchiveConfig, String>,
        from_connect: bool,
    ) {
        self.archive_ui.busy = None;
        match result {
            Ok(cfg) => {
                if from_connect {
                    self.archive_ui.passphrase.clear();
                    self.archive_ui.status =
                        Some((true, "Đã kết nối và bật lưu trữ.".into()));
                }
                self.archive_ui.form = cfg.clone();
                self.archive_ui.saved = Some(cfg);
            }
            Err(e) => {
                self.archive_ui.status = Some((false, e));
            }
        }
    }

    pub(super) fn archive_on_saved(&mut self, result: Result<ArchiveConfig, String>) {
        self.archive_ui.busy = None;
        match result {
            Ok(cfg) => {
                self.archive_ui.status = Some((true, "Đã lưu cài đặt lưu trữ.".into()));
                self.archive_ui.form = cfg.clone();
                self.archive_ui.saved = Some(cfg);
            }
            Err(e) => self.archive_ui.status = Some((false, e)),
        }
    }

    pub(super) fn archive_on_backup(
        &mut self,
        ctx: &egui::Context,
        reason: BackupReason,
        result: Result<Option<(BackupReport, i64)>, String>,
    ) {
        if self.archive_ui.busy.is_some() && reason != BackupReason::BeforeExit {
            self.archive_ui.busy = None;
        }
        match result {
            Ok(Some((report, at))) => {
                let uin = self.user_uin.clone();
                if let Some(cfg) = self.archive_ui.saved.as_mut() {
                    cfg.last_backup_ms.insert(uin.clone(), at);
                }
                self.archive_ui.form.last_backup_ms.insert(uin, at);
                let text = format!("Đã sao lưu: {}", describe_report(&report));
                self.archive_ui.status = Some((true, text.clone()));
                self.archive_ui.last_report = Some(report);
                if reason == BackupReason::Manual {
                    self.show_toast(format!("✅ {text}"));
                }
            }
            Ok(None) => {
                if reason == BackupReason::Manual {
                    self.show_toast("Đang có một lần sao lưu khác, thử lại sau.");
                }
            }
            Err(e) => {
                self.archive_ui.status = Some((false, format!("Sao lưu lỗi: {e}")));
                if reason != BackupReason::BeforeExit {
                    self.show_toast(format!("⚠️ Sao lưu lỗi: {e}"));
                }
            }
        }
        if reason == BackupReason::BeforeExit && self.archive_ui.exit_started.is_some() {
            self.archive_ui.exit_ready = true;
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }

    pub(super) fn archive_on_restore(
        &mut self,
        result: Result<crate::archive::engine::RestoreReport, String>,
    ) {
        self.archive_ui.busy = None;
        let (ok, text) = match result {
            Ok(r) => (
                true,
                format!(
                    "Đã khôi phục {} tin từ {} segment ({} hội thoại mới). Danh sách đang được làm mới.",
                    r.rows, r.segments, r.threads
                ),
            ),
            Err(e) => (false, format!("Khôi phục lỗi: {e}")),
        };
        self.show_toast(if ok { format!("✅ {text}") } else { format!("⚠️ {text}") });
        self.archive_ui.status = Some((ok, text));
    }

    pub(super) fn render_archive_settings(&mut self, ui: &mut egui::Ui, pal: &ThemePalette) {
        let section = |ui: &mut egui::Ui, title: &str| {
            ui.add_space(4.0);
            ui.label(
                RichText::new(title)
                    .color(pal.text_primary)
                    .size(13.5)
                    .strong(),
            );
            ui.add_space(6.0);
        };
        let card = |ui: &mut egui::Ui, add: &mut dyn FnMut(&mut egui::Ui)| {
            egui::Frame::none()
                .fill(pal.bg_elevated)
                .stroke(Stroke::new(1.0_f32, pal.border))
                .rounding(Rounding::same(8.0))
                .inner_margin(Margin::symmetric(14.0, 12.0))
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    ui.vertical(|ui| add(ui));
                });
            ui.add_space(14.0);
        };
        let hint = |ui: &mut egui::Ui, text: &str| {
            ui.label(RichText::new(text).color(pal.text_secondary).size(12.0));
        };

        let enabled = self.archive_ui.saved.as_ref().is_some_and(|c| c.enabled);
        let busy = self.archive_ui.busy;
        let mut connect = false;
        let mut save = false;
        let mut backup_now = false;
        let mut restore = false;
        let mut disable = false;

        section(ui, "Kho lưu trữ (S3 / Cloudflare R2 / Google Cloud Storage / MinIO)");
        card(ui, &mut |ui| {
            hint(
                ui,
                "Zalo không giữ lịch sử chat lâu dài. Sao lưu tin nhắn và media của từng tài khoản lên bucket của bạn; có thể giới hạn dữ liệu trên máy và tải lại tin cũ khi cuộn tới.",
            );
            ui.add_space(8.0);
            let form = &mut self.archive_ui.form;
            field_row(ui, pal, "Dịch vụ", TARGET_LABEL_W, |ui, _| {
                let before = form.provider;
                egui::ComboBox::from_id_salt("archive_provider")
                    .selected_text(provider_label(form.provider))
                    .width(200.0)
                    .show_ui(ui, |ui| {
                        for p in [
                            Provider::S3,
                            Provider::R2,
                            Provider::Gcs,
                            Provider::Minio,
                            Provider::Custom,
                        ] {
                            ui.selectable_value(&mut form.provider, p, provider_label(p));
                        }
                    });
                if form.provider != before {
                    let (endpoint, region, path_style) = form.provider.defaults();
                    if form.endpoint.trim().is_empty() || form.endpoint.contains('<') {
                        form.endpoint = endpoint.into();
                    }
                    form.region = region.into();
                    form.path_style = path_style;
                }
            });
            let hint_endpoint = form.provider.defaults().0;
            field_row(ui, pal, "Endpoint", TARGET_LABEL_W, |ui, w| {
                ui.add(
                    egui::TextEdit::singleline(&mut form.endpoint)
                        .hint_text(hint_endpoint)
                        .desired_width(w),
                );
            });
            field_row(ui, pal, "Region", TARGET_LABEL_W, |ui, w| {
                ui.add(egui::TextEdit::singleline(&mut form.region).desired_width(w.min(200.0)));
            });
            field_row(ui, pal, "Bucket", TARGET_LABEL_W, |ui, w| {
                ui.add(egui::TextEdit::singleline(&mut form.bucket).desired_width(w));
            });
            field_row(ui, pal, "Thư mục (prefix)", TARGET_LABEL_W, |ui, w| {
                ui.add(
                    egui::TextEdit::singleline(&mut form.prefix)
                        .hint_text("không bắt buộc")
                        .desired_width(w),
                );
            });
            field_row(ui, pal, "Access key", TARGET_LABEL_W, |ui, w| {
                ui.add(egui::TextEdit::singleline(&mut form.access_key).desired_width(w));
            });
            let show_secret = &mut self.archive_ui.show_secret;
            field_row(ui, pal, "Secret key", TARGET_LABEL_W, |ui, w| {
                ui.add(
                    egui::TextEdit::singleline(&mut form.secret_key)
                        .password(!*show_secret)
                        .desired_width((w - 64.0).max(80.0)),
                );
                ui.checkbox(show_secret, "Hiện");
            });
            ui.add_space(4.0);
            ui.checkbox(
                &mut self.archive_ui.form.path_style,
                "Dùng path-style URL (R2, GCS, MinIO)",
            );
            if self.archive_ui.form.provider == Provider::Gcs {
                hint(
                    ui,
                    "Google Cloud Storage: tạo HMAC key trong Cloud Storage → Settings → Interoperability.",
                );
            }
        });

        section(ui, "Mã hoá");
        card(ui, &mut |ui| {
            ui.checkbox(
                &mut self.archive_ui.form.encrypt,
                "Mã hoá dữ liệu trước khi tải lên (khuyến nghị)",
            );
            if self.archive_ui.form.encrypt {
                hint(
                    ui,
                    "AES-256-GCM, khoá tạo từ mật khẩu bằng Argon2id. Nhà cung cấp và ai lộ key bucket đều không đọc được tin nhắn. Quên mật khẩu thì KHÔNG khôi phục được.",
                );
                ui.add_space(6.0);
                let remembered = self.archive_ui.form.master_key.is_some();
                let passphrase = &mut self.archive_ui.passphrase;
                field_row(ui, pal, "Mật khẩu", TARGET_LABEL_W, |ui, w| {
                    ui.add(
                        egui::TextEdit::singleline(passphrase)
                            .password(true)
                            .hint_text(if remembered {
                                "đã lưu trên máy"
                            } else {
                                "mật khẩu sao lưu"
                            })
                            .desired_width(w),
                    );
                });
                hint(
                    ui,
                    if remembered {
                        "Để trống nếu không đổi."
                    } else {
                        "Lần đầu: đặt mật khẩu mới. Máy khác: nhập mật khẩu đã đặt."
                    },
                );
                ui.checkbox(
                    &mut self.archive_ui.form.remember_key,
                    "Lưu khoá trên máy này để sao lưu tự động",
                );
                if !self.archive_ui.form.remember_key {
                    hint(ui, "Không lưu khoá: chỉ sao lưu khi bạn bấm và nhập lại mật khẩu.");
                }
            } else {
                ui.label(
                    RichText::new(
                        "⚠️ Không mã hoá: ai có quyền đọc bucket đều đọc được toàn bộ tin nhắn. Chỉ nên dùng với bucket riêng bạn kiểm soát (vd. MinIO trong mạng nội bộ).",
                    )
                    .color(pal.danger_text)
                    .size(12.0),
                );
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let label = if enabled { "Lưu & kết nối lại" } else { "Kết nối & bật lưu trữ" };
                if ui
                    .add_enabled(busy.is_none(), egui::Button::new(RichText::new(label).strong()))
                    .clicked()
                {
                    connect = true;
                }
                if enabled
                    && ui
                        .add_enabled(busy.is_none(), egui::Button::new("Tắt lưu trữ"))
                        .on_hover_text("Ngừng sao lưu; dữ liệu trên bucket và trên máy được giữ nguyên.")
                        .clicked()
                {
                    disable = true;
                }
            });
        });

        if enabled {
            section(ui, "Sao lưu");
            card(ui, &mut |ui| {
                let last = self
                    .archive_ui
                    .saved
                    .as_ref()
                    .and_then(|c| c.last_backup_ms.get(&self.user_uin).copied());
                ui.label(
                    RichText::new(match last {
                        Some(ms) => format!("Lần sao lưu gần nhất: {}", format_time(ms)),
                        None => "Tài khoản này chưa được sao lưu.".into(),
                    })
                    .color(pal.text_primary)
                    .size(12.8),
                );
                if let Some(r) = &self.archive_ui.last_report {
                    hint(ui, &describe_report(r));
                }
                ui.add_space(6.0);
                let hours = &mut self.archive_ui.form.auto_backup_hours;
                field_row(ui, pal, "Tự động sao lưu", RETENTION_LABEL_W, |ui, _| {
                    let text = |h: u32| match h {
                        0 => "Tắt".to_string(),
                        h => format!("Mỗi {h} giờ"),
                    };
                    egui::ComboBox::from_id_salt("archive_auto_hours")
                        .selected_text(text(*hours))
                        .width(140.0)
                        .show_ui(ui, |ui| {
                            for h in [0, 1, 6, 12, 24] {
                                ui.selectable_value(hours, h, text(h));
                            }
                        });
                });
                hint(ui, "Khi bật, app cũng sao lưu nhanh lúc thoát (tối đa 10 giây).");
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            busy.is_none() && self.is_logged_in,
                            egui::Button::new(RichText::new(format!("{} Sao lưu ngay", lucide::CLOUD)).strong()),
                        )
                        .clicked()
                    {
                        backup_now = true;
                    }
                    if ui
                        .add_enabled(
                            busy.is_none() && self.is_logged_in,
                            egui::Button::new(format!("{} Khôi phục từ kho", lucide::REFRESH)),
                        )
                        .on_hover_text("Tải toàn bộ tin đã sao lưu của tài khoản này về máy. Không xoá dữ liệu đang có.")
                        .clicked()
                    {
                        restore = true;
                    }
                });
            });

            section(ui, "Giữ lại trên máy (tài khoản hiện tại)");
            card(ui, &mut |ui| {
                hint(
                    ui,
                    "Chỉ xoá trên máy những tin/tệp đã có trên kho lưu trữ; tin đã lưu, tin có nhắc hẹn và hội thoại đang mở luôn được giữ. Tin cũ được tải lại khi bạn bấm \"Đồng bộ thêm lịch sử\" trong hội thoại. 0 = không giới hạn.",
                );
                ui.add_space(6.0);
                let uin = self.user_uin.clone();
                let mut policy: Retention = self.archive_ui.form.retention_for(&uin);
                field_row(ui, pal, "Giữ tin trong", RETENTION_LABEL_W, |ui, _| {
                    ui.add(egui::DragValue::new(&mut policy.keep_days).range(0..=3650).suffix(" ngày"));
                });
                field_row(ui, pal, "Tin nhắn tối đa", RETENTION_LABEL_W, |ui, _| {
                    ui.add(egui::DragValue::new(&mut policy.max_db_mb).range(0..=100_000).suffix(" MB"));
                });
                field_row(ui, pal, "Media tối đa", RETENTION_LABEL_W, |ui, _| {
                    ui.add(egui::DragValue::new(&mut policy.max_media_mb).range(0..=1_000_000).suffix(" MB"));
                });
                if !uin.is_empty() {
                    self.archive_ui.form.retention.insert(uin, policy);
                }
                ui.add_space(8.0);
                if ui
                    .add_enabled(busy.is_none(), egui::Button::new("Lưu cài đặt"))
                    .clicked()
                {
                    save = true;
                }
            });
        }

        if let Some(text) = busy {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(RichText::new(text).color(pal.text_secondary).size(12.5));
            });
        } else if let Some((ok, text)) = &self.archive_ui.status {
            ui.label(
                RichText::new(text)
                    .color(if *ok { pal.accent_online } else { pal.danger_text })
                    .size(12.5),
            );
        }

        if connect {
            if let Err(e) = self.archive_ui.form.validate() {
                self.archive_ui.status = Some((false, e.to_string()));
            } else if self.archive_ui.form.encrypt
                && self.archive_ui.passphrase.trim().is_empty()
                && self.archive_ui.form.master_key.is_none()
            {
                self.archive_ui.status = Some((false, "Nhập mật khẩu sao lưu".into()));
            } else {
                self.archive_ui.busy = Some(if self.archive_ui.form.encrypt {
                    "Đang kết nối và tạo khoá (vài giây)…"
                } else {
                    "Đang kết nối…"
                });
                let cfg = self.archive_ui.form.clone();
                let passphrase = std::mem::take(&mut self.archive_ui.passphrase);
                self.archive_send(WorkerCmd::ArchiveConnect { cfg, passphrase });
            }
        }
        if save || disable {
            let mut cfg = self.archive_ui.form.clone();
            if disable {
                cfg.enabled = false;
            }
            self.archive_ui.busy = Some("Đang lưu…");
            self.archive_send(WorkerCmd::ArchiveSave { cfg });
        }
        if backup_now {
            self.archive_ui.busy = Some("Đang sao lưu…");
            let keep = self.open_thread_ids();
            self.archive_send(WorkerCmd::ArchiveBackup {
                reason: BackupReason::Manual,
                keep_threads: keep,
            });
        }
        if restore {
            self.archive_ui.busy = Some("Đang khôi phục từ kho lưu trữ…");
            self.archive_send(WorkerCmd::ArchiveRestore);
        }
    }
}
