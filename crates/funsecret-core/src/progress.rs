//! 终端同步进度条封装（基于 `indicatif`，对齐 `funget-core` 风格）。
//!
//! 仅在 `enabled == true` 且 `stderr` 为交互终端（TTY）时渲染动态进度条，
//! 非 TTY（管道、CI、uTools 插件、重定向）或 `--json` / `--silent` 模式下自动隐藏。

use std::io::IsTerminal;
use std::time::Duration;

use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};

pub(crate) struct SyncProgress {
    bar: ProgressBar,
    enabled: bool,
}

impl SyncProgress {
    /// 启动不定长 Spinner（用于连接外部数据库和拉取源记录阶段）。
    pub(crate) fn start(label: &str, enabled: bool) -> Self {
        if !enabled || !std::io::stderr().is_terminal() {
            return Self {
                bar: ProgressBar::hidden(),
                enabled: false,
            };
        }
        let bar = ProgressBar::with_draw_target(None, ProgressDrawTarget::stderr());
        bar.set_prefix(label.to_string());
        if let Ok(style) =
            ProgressStyle::with_template("{spinner:.cyan} {prefix}: {msg} ({elapsed})")
        {
            bar.set_style(style);
        }
        bar.set_message("connecting...");
        bar.enable_steady_tick(Duration::from_millis(100));
        Self { bar, enabled: true }
    }

    /// 拿到总条目数后切换为类似 `tqdm` 的确定进度条。
    pub(crate) fn set_total(&self, total: usize) {
        if !self.enabled {
            return;
        }
        self.bar.disable_steady_tick();
        self.bar.set_length(total as u64);
        self.bar.set_position(0);
        if let Ok(style) = ProgressStyle::with_template(
            "{prefix} [{bar:32.cyan/blue}] {pos}/{len} ({elapsed_precise})",
        ) {
            self.bar.set_style(style.progress_chars("=> "));
        }
    }

    pub(crate) fn inc(&self, delta: u64) {
        if self.enabled {
            self.bar.inc(delta);
        }
    }

    pub(crate) fn finish(&self) {
        if self.enabled {
            self.bar.finish_and_clear();
        }
    }
}

impl Drop for SyncProgress {
    fn drop(&mut self) {
        if self.enabled && !self.bar.is_finished() {
            self.bar.finish_and_clear();
        }
    }
}
