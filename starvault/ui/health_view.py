"""Vault Health & Security Advisor UI view for StarVault.

Scans the decrypted vault in memory and provides actionable security insights,
detecting reused passwords, weak credentials, expiring tokens, and duplicates.
"""

from typing import Callable, Optional
import customtkinter as ctk

from starvault.database import Database
from starvault.health import HealthIssue, VaultHealthAdvisor, VaultHealthReport
from starvault.ui.theme import (
    ACCENT_HOVER,
    ACCENT_PRIMARY,
    BG_CARD,
    BG_INPUT,
    BG_ROOT,
    BG_SUBTLE,
    BORDER_COLOR,
    COLOR_DANGER,
    COLOR_SUCCESS,
    COLOR_WARNING,
    TEXT_MUTED,
    TEXT_PRIMARY,
    TEXT_SECONDARY,
    get_font,
    get_mono_font,
)


class HealthView(ctk.CTkFrame):
    """Dashboard view for analyzing vault security posture and remediating issues."""

    def __init__(
        self,
        parent,
        database: Database,
        encryption_key: bytes,
        on_review_entry: Optional[Callable[[str], None]] = None,
        **kwargs,
    ):
        super().__init__(parent, fg_color=BG_ROOT, **kwargs)
        self.database = database
        self.encryption_key = encryption_key
        self.on_review_entry = on_review_entry
        self.report: Optional[VaultHealthReport] = None

        self._build_ui()
        self.refresh()

    def _build_ui(self):
        # Header banner
        header = ctk.CTkFrame(self, fg_color=BG_CARD, height=64, corner_radius=0)
        header.pack(fill="x")

        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.pack(side="left", padx=24, pady=12)

        ctk.CTkLabel(
            title_frame,
            text="🛡️ Vault Health Advisor",
            font=get_font(18, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(anchor="w")

        ctk.CTkLabel(
            title_frame,
            text="In-memory security scan: duplicate credentials, stale passwords, and expiring keys.",
            font=get_font(11),
            text_color=TEXT_MUTED,
        ).pack(anchor="w")

        # Re-Scan button
        ctk.CTkButton(
            header,
            text="🔄 Re-Scan Vault",
            font=get_font(12, "bold"),
            width=130,
            height=34,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=self.refresh,
        ).pack(side="right", padx=24, pady=15)

        # Content container
        self.scroll_content = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.scroll_content.pack(fill="both", expand=True, padx=24, pady=16)

        # Top summary card (Score badge + Quick metrics)
        self.summary_card = ctk.CTkFrame(
            self.scroll_content,
            fg_color=BG_CARD,
            corner_radius=12,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        self.summary_card.pack(fill="x", pady=(0, 16))

        self.score_container = ctk.CTkFrame(self.summary_card, fg_color="transparent")
        self.score_container.pack(fill="x", padx=20, pady=16)

        # Issues container
        self.issues_label = ctk.CTkLabel(
            self.scroll_content,
            text="FINDINGS & ACTIONABLE ADVICE",
            font=get_font(12, "bold"),
            text_color=ACCENT_PRIMARY,
        )
        self.issues_label.pack(anchor="w", pady=(8, 8))

        self.issues_list_frame = ctk.CTkFrame(self.scroll_content, fg_color="transparent")
        self.issues_list_frame.pack(fill="both", expand=True)

    def refresh(self):
        """Performs in-memory audit of all decrypted entries and updates UI."""
        entries = self.database.get_all_entries(self.encryption_key)
        advisor = VaultHealthAdvisor()
        self.report = advisor.analyze(entries)
        self._render_report(self.report)

    def _render_report(self, report: VaultHealthReport):
        # 1. Rebuild summary card
        for child in self.score_container.winfo_children():
            child.destroy()

        score_color = COLOR_SUCCESS if report.overall_score >= 80 else (COLOR_WARNING if report.overall_score >= 60 else COLOR_DANGER)

        # Left score badge
        badge_frame = ctk.CTkFrame(
            self.score_container,
            fg_color=BG_INPUT,
            corner_radius=10,
            border_width=2,
            border_color=score_color,
            width=130,
            height=90,
        )
        badge_frame.pack(side="left", padx=(0, 24), pady=4)
        badge_frame.pack_propagate(False)

        ctk.CTkLabel(
            badge_frame,
            text=f"{report.overall_score}",
            font=get_font(28, "bold"),
            text_color=score_color,
        ).pack(pady=(12, 0))

        ctk.CTkLabel(
            badge_frame,
            text=f"GRADE {report.grade} / 100",
            font=get_font(10, "bold"),
            text_color=TEXT_SECONDARY,
        ).pack()

        # Metrics columns
        metrics_frame = ctk.CTkFrame(self.score_container, fg_color="transparent")
        metrics_frame.pack(side="left", fill="both", expand=True)

        ctk.CTkLabel(
            metrics_frame,
            text=f"Analyzed {report.total_entries_analyzed} Vault Entries",
            font=get_font(14, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(anchor="w")

        status_text = (
            "No critical issues detected. Your vault security posture is strong."
            if not report.issues
            else f"Identified {len(report.issues)} potential vulnerabilities or hygiene issues."
        )
        ctk.CTkLabel(
            metrics_frame,
            text=status_text,
            font=get_font(12),
            text_color=TEXT_MUTED,
        ).pack(anchor="w", pady=(2, 10))

        # Quick stats row
        stats_row = ctk.CTkFrame(metrics_frame, fg_color="transparent")
        stats_row.pack(fill="x")

        self._create_metric_pill(stats_row, "Duplicate Pwds", report.duplicate_passwords_count, COLOR_DANGER if report.duplicate_passwords_count > 0 else TEXT_MUTED)
        self._create_metric_pill(stats_row, "Weak Pwds", report.weak_passwords_count, COLOR_WARNING if report.weak_passwords_count > 0 else TEXT_MUTED)
        self._create_metric_pill(stats_row, "Stale Pwds (>180d)", report.stale_passwords_count, COLOR_WARNING if report.stale_passwords_count > 0 else TEXT_MUTED)
        self._create_metric_pill(stats_row, "Expiring Keys", report.expiring_keys_count, COLOR_DANGER if report.expiring_keys_count > 0 else TEXT_MUTED)
        self._create_metric_pill(stats_row, "Name Clones", report.duplicate_names_count, TEXT_MUTED)

        # 2. Rebuild issues list
        for child in self.issues_list_frame.winfo_children():
            child.destroy()

        if not report.issues:
            empty_card = ctk.CTkFrame(
                self.issues_list_frame,
                fg_color=BG_CARD,
                corner_radius=10,
                border_width=1,
                border_color=BORDER_COLOR,
            )
            empty_card.pack(fill="x", pady=10)
            ctk.CTkLabel(
                empty_card,
                text="🎉 All Clear!",
                font=get_font(16, "bold"),
                text_color=COLOR_SUCCESS,
            ).pack(pady=(20, 4))
            ctk.CTkLabel(
                empty_card,
                text="No reused passwords, duplicate entries, or expired credentials found in this vault.",
                font=get_font(12),
                text_color=TEXT_MUTED,
            ).pack(pady=(0, 20))
            return

        for issue in report.issues:
            self._render_issue_card(issue)

    def _create_metric_pill(self, parent, label: str, count: int, color: str):
        pill = ctk.CTkFrame(parent, fg_color=BG_INPUT, corner_radius=6, border_width=1, border_color=BORDER_COLOR)
        pill.pack(side="left", padx=(0, 10))
        ctk.CTkLabel(
            pill,
            text=f"{count}",
            font=get_font(12, "bold"),
            text_color=color,
        ).pack(side="left", padx=(10, 4), pady=4)
        ctk.CTkLabel(
            pill,
            text=label,
            font=get_font(11),
            text_color=TEXT_SECONDARY,
        ).pack(side="left", padx=(0, 10), pady=4)

    def _render_issue_card(self, issue: HealthIssue):
        card = ctk.CTkFrame(
            self.issues_list_frame,
            fg_color=BG_CARD,
            corner_radius=10,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        card.pack(fill="x", pady=6)

        header = ctk.CTkFrame(card, fg_color="transparent")
        header.pack(fill="x", padx=16, pady=(12, 4))

        # Severity Badge
        sev_color = COLOR_DANGER if issue.severity == "high" else (COLOR_WARNING if issue.severity == "medium" else TEXT_MUTED)
        sev_badge = ctk.CTkFrame(header, fg_color=BG_INPUT, corner_radius=4, border_width=1, border_color=sev_color)
        sev_badge.pack(side="left", padx=(0, 10))
        ctk.CTkLabel(
            sev_badge,
            text=issue.severity.upper(),
            font=get_font(10, "bold"),
            text_color=sev_color,
        ).pack(padx=8, pady=2)

        # Title
        ctk.CTkLabel(
            header,
            text=issue.title,
            font=get_font(13, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(side="left")

        # Action Buttons on right
        if self.on_review_entry and issue.entry_ids:
            btn_box = ctk.CTkFrame(header, fg_color="transparent")
            btn_box.pack(side="right")
            for idx, entry_id in enumerate(issue.entry_ids[:2]):
                title = issue.entry_titles[idx] if idx < len(issue.entry_titles) else "Entry"
                short_title = (title[:12] + "..") if len(title) > 12 else title
                ctk.CTkButton(
                    btn_box,
                    text=f"Review '{short_title}'",
                    font=get_font(11, "bold"),
                    width=110,
                    height=28,
                    fg_color=ACCENT_PRIMARY,
                    hover_color=ACCENT_HOVER,
                    text_color="#000000",
                    command=lambda eid=entry_id: self.on_review_entry(eid),
                ).pack(side="left", padx=4)

        # Description
        body = ctk.CTkFrame(card, fg_color="transparent")
        body.pack(fill="x", padx=16, pady=(0, 12))

        ctk.CTkLabel(
            body,
            text=issue.description,
            font=get_font(12),
            text_color=TEXT_SECONDARY,
            wraplength=600,
            justify="left",
        ).pack(anchor="w")

        # Recommendation
        rec_row = ctk.CTkFrame(body, fg_color="transparent")
        rec_row.pack(anchor="w", pady=(6, 0))
        ctk.CTkLabel(
            rec_row,
            text="💡 Remediation: ",
            font=get_font(11, "bold"),
            text_color=COLOR_WARNING,
        ).pack(side="left")
        ctk.CTkLabel(
            rec_row,
            text=issue.recommendation,
            font=get_font(11),
            text_color=TEXT_MUTED,
            wraplength=550,
            justify="left",
        ).pack(side="left")
