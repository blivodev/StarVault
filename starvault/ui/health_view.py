"""Vault Health & Security Advisor UI view for StarVault.

Scans the decrypted vault in memory and provides actionable security insights:
- Reused / duplicate passwords
- Weak passwords
- Stale credentials (>180 / >365 days)
- Expiring API keys, tokens, and certificates
- One-click automated remediation (⚡ Auto-Fix)
- Expiry notifications and alerts
- Optional AI / LLM Security & Hygiene Advisor (OpenAI, Gemini, Claude, OpenRouter, DeepInfra, Fireworks, Ollama)
"""

import threading
from typing import Callable, Optional
import customtkinter as ctk

from starvault.ai_advisor import AI_PROVIDERS, AIAdvisor, AIAnalysisResult, AIRemediationAction
from starvault.database import Database
from starvault.health import HealthIssue, VaultHealthAdvisor, VaultHealthReport, fix_health_issue
from starvault.organizer import (
    auto_organize_files,
    auto_organize_vault,
    deduplicate_vault,
    find_duplicates,
    find_ghost_and_stale,
    infer_category,
    infer_tags,
    normalize_title,
    purge_ghost_entries,
    sort_entries,
)
from starvault.ui.theme import (
    ACCENT_HOVER,
    ACCENT_INDIGO,
    ACCENT_PRIMARY,
    ACCENT_PURPLE,
    BG_CARD,
    BG_CARD_HOVER,
    BG_INPUT,
    BG_ROOT,
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
    """Dashboard view for analyzing vault security posture, auto-fixing issues, and running AI audits."""

    def __init__(
        self,
        parent,
        database: Database,
        encryption_key: bytes,
        on_review_entry: Optional[Callable[[str], None]] = None,
        on_vault_updated: Optional[Callable[[], None]] = None,
        **kwargs,
    ) -> None:
        super().__init__(parent, fg_color=BG_ROOT, **kwargs)
        self.database = database
        self.encryption_key = encryption_key
        self.on_review_entry = on_review_entry
        self.on_vault_updated = on_vault_updated
        self.report: Optional[VaultHealthReport] = None
        self.ai_result: Optional[AIAnalysisResult] = None
        self._ai_scanning = False

        self._build_ui()
        self.refresh()

    def _build_ui(self) -> None:
        # Header banner
        header = ctk.CTkFrame(self, fg_color=BG_CARD, height=64, corner_radius=0)
        header.pack(fill="x")

        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.pack(side="left", padx=24, pady=12)

        ctk.CTkLabel(
            title_frame,
            text="🛡️ Vault Health & Remediation Advisor",
            font=get_font(18, "bold"),
            text_color=TEXT_PRIMARY,
        ).pack(anchor="w")

        ctk.CTkLabel(
            title_frame,
            text="In-memory security scan: duplicate credentials, stale passwords, and 1-click auto-fix.",
            font=get_font(11),
            text_color=TEXT_MUTED,
        ).pack(anchor="w")

        # Action Buttons on header
        act_box = ctk.CTkFrame(header, fg_color="transparent")
        act_box.pack(side="right", padx=24, pady=15)

        ctk.CTkButton(
            act_box,
            text="🔄 Re-Scan Vault",
            font=get_font(12, "bold"),
            width=130,
            height=34,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=self.refresh,
        ).pack(side="right", padx=(8, 0))

        # Content container
        self.scroll_content = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.scroll_content.pack(fill="both", expand=True, padx=24, pady=16)

        # Status / Feedback toast banner
        self.status_banner = ctk.CTkLabel(
            self.scroll_content,
            text="",
            font=get_font(12, "bold"),
            text_color=COLOR_SUCCESS,
        )
        self.status_banner.pack(anchor="w", pady=(0, 4))

        # Top summary card (Score badge + Quick metrics)
        self.summary_card = ctk.CTkFrame(
            self.scroll_content,
            fg_color=BG_CARD,
            corner_radius=12,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        self.summary_card.pack(fill="x", pady=(0, 12))

        self.score_container = ctk.CTkFrame(self.summary_card, fg_color="transparent")
        self.score_container.pack(fill="x", padx=20, pady=16)

        # Expiry Alert Banner (hidden unless expiring keys exist)
        self.expiry_alert_frame = ctk.CTkFrame(
            self.scroll_content,
            fg_color=BG_INPUT,
            corner_radius=8,
            border_width=1,
            border_color=COLOR_DANGER,
        )
        self.expiry_alert_lbl = ctk.CTkLabel(
            self.expiry_alert_frame,
            text="",
            font=get_font(12, "bold"),
            text_color=COLOR_DANGER,
            padx=16,
            pady=10,
        )
        self.expiry_alert_lbl.pack(side="left")

        # Auto-Organize & Smart Vault Studio Section
        self._build_auto_organize_section()

        # AI Advisor Section
        self._build_ai_advisor_section()

        # Findings Header
        self.issues_label = ctk.CTkLabel(
            self.scroll_content,
            text="FINDINGS & ACTIONABLE ADVICE",
            font=get_font(12, "bold"),
            text_color=ACCENT_PRIMARY,
        )
        self.issues_label.pack(anchor="w", pady=(14, 8))

        self.issues_list_frame = ctk.CTkFrame(self.scroll_content, fg_color="transparent")
        self.issues_list_frame.pack(fill="both", expand=True)

    def _build_auto_organize_section(self) -> None:
        """Builds interactive Auto-Organize & Smart Vault Studio toolbar card."""
        self.organize_card = ctk.CTkFrame(
            self.scroll_content,
            fg_color=BG_CARD,
            corner_radius=10,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        self.organize_card.pack(fill="x", pady=(0, 14))

        org_header = ctk.CTkFrame(self.organize_card, fg_color="transparent")
        org_header.pack(fill="x", padx=16, pady=(12, 4))

        ctk.CTkLabel(
            org_header,
            text="🗂️ Auto-Organize & Smart Vault Studio",
            font=get_font(13, "bold"),
            text_color=ACCENT_PRIMARY,
        ).pack(side="left")

        ctk.CTkLabel(
            org_header,
            text="Automated grouping, smart tags, title cleanup, deduplication, and file sorting",
            font=get_font(11),
            text_color=TEXT_MUTED,
        ).pack(side="left", padx=12)

        # Main Action Buttons Row
        row_btn = ctk.CTkFrame(self.organize_card, fg_color="transparent")
        row_btn.pack(fill="x", padx=16, pady=(6, 8))

        ctk.CTkButton(
            row_btn,
            text="⚡ Auto-Organize All",
            font=get_font(11, "bold"),
            height=32,
            fg_color=COLOR_SUCCESS,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            command=self._handle_auto_organize_all,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            row_btn,
            text="📁 Auto-Group",
            font=get_font(11),
            height=32,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=self._handle_auto_group,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            row_btn,
            text="🏷️ Auto-Tag",
            font=get_font(11),
            height=32,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=self._handle_auto_tag,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            row_btn,
            text="🧹 Merge Duplicates",
            font=get_font(11),
            height=32,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=self._handle_merge_duplicates,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            row_btn,
            text="🗑️ Purge Ghosts",
            font=get_font(11),
            height=32,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=self._handle_purge_ghosts,
        ).pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            row_btn,
            text="📂 Organize Files",
            font=get_font(11),
            height=32,
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=self._handle_auto_organize_files,
        ).pack(side="left")

        # Sorting & Reorganization Controls Row
        row_sort = ctk.CTkFrame(self.organize_card, fg_color="transparent")
        row_sort.pack(fill="x", padx=16, pady=(0, 12))

        ctk.CTkLabel(
            row_sort,
            text="Smart Re-Sort:",
            font=get_font(11, "bold"),
            text_color=TEXT_SECONDARY,
        ).pack(side="left", padx=(0, 8))

        self.sort_combo = ctk.CTkComboBox(
            row_sort,
            values=[
                "Category (A-Z)",
                "Title (A-Z)",
                "Title (Z-A)",
                "Security Risk (Weakest First)",
                "Recency (Modified First)",
                "Type (Servers -> Keys)",
            ],
            width=220,
            height=30,
            font=get_font(11),
        )
        self.sort_combo.set("Category (A-Z)")
        self.sort_combo.pack(side="left", padx=(0, 8))

        ctk.CTkButton(
            row_sort,
            text="🔀 Apply Auto-Sort",
            font=get_font(11, "bold"),
            width=130,
            height=30,
            fg_color=ACCENT_INDIGO,
            hover_color=ACCENT_HOVER,
            command=self._handle_apply_sort,
        ).pack(side="left")

    def _build_ai_advisor_section(self) -> None:
        """Builds expandable AI/LLM Security & Hygiene Advisor section."""
        self.ai_card = ctk.CTkFrame(
            self.scroll_content,
            fg_color=BG_CARD,
            corner_radius=10,
            border_width=1,
            border_color=BORDER_COLOR,
        )
        self.ai_card.pack(fill="x", pady=(0, 14))

        ai_header = ctk.CTkFrame(self.ai_card, fg_color="transparent")
        ai_header.pack(fill="x", padx=16, pady=12)

        ctk.CTkLabel(
            ai_header,
            text="🤖 AI Security & Hygiene Advisor (Optional)",
            font=get_font(13, "bold"),
            text_color=ACCENT_INDIGO,
        ).pack(side="left")

        ctk.CTkLabel(
            ai_header,
            text="Zero-knowledge: NEVER sends unencrypted passwords",
            font=get_font(11),
            text_color=TEXT_MUTED,
        ).pack(side="left", padx=12)

        self.ai_expand_btn = ctk.CTkButton(
            ai_header,
            text="▼ Configure & Scan",
            width=140,
            height=30,
            font=get_font(11),
            fg_color=BG_INPUT,
            hover_color=BORDER_COLOR,
            command=self._toggle_ai_panel,
        )
        self.ai_expand_btn.pack(side="right")

        # Collapsible content
        self.ai_body = ctk.CTkFrame(self.ai_card, fg_color="transparent")
        self._ai_expanded = False

        # Provider Controls Row
        row1 = ctk.CTkFrame(self.ai_body, fg_color="transparent")
        row1.pack(fill="x", padx=16, pady=(0, 10))

        # Provider Selector
        col_prov = ctk.CTkFrame(row1, fg_color="transparent")
        col_prov.pack(side="left", fill="x", expand=True, padx=(0, 6))
        ctk.CTkLabel(col_prov, text="AI Service Provider", font=get_font(11)).pack(anchor="w")

        provider_names = [cfg["name"] for k, cfg in AI_PROVIDERS.items()]
        self.provider_key_map = {cfg["name"]: k for k, cfg in AI_PROVIDERS.items()}

        self.ai_provider_combo = ctk.CTkComboBox(
            col_prov,
            values=provider_names,
            command=self._on_ai_provider_changed,
            height=34,
            font=get_font(11),
        )
        self.ai_provider_combo.set("Ollama (Local)")
        self.ai_provider_combo.pack(fill="x", pady=(3, 0))

        # Model Input
        col_model = ctk.CTkFrame(row1, fg_color="transparent")
        col_model.pack(side="left", fill="x", expand=True, padx=6)
        ctk.CTkLabel(col_model, text="Model Name", font=get_font(11)).pack(anchor="w")
        self.ai_model_entry = ctk.CTkEntry(col_model, placeholder_text="llama3, gpt-4o-mini, etc.", height=34)
        self.ai_model_entry.insert(0, "llama3")
        self.ai_model_entry.pack(fill="x", pady=(3, 0))

        # API Key Input
        col_key = ctk.CTkFrame(row1, fg_color="transparent")
        col_key.pack(side="right", fill="x", expand=True, padx=(6, 0))
        ctk.CTkLabel(col_key, text="API Key (Leave empty for Ollama)", font=get_font(11)).pack(anchor="w")
        self.ai_key_entry = ctk.CTkEntry(col_key, placeholder_text="sk-...", show="•", height=34)
        self.ai_key_entry.pack(fill="x", pady=(3, 0))

        # Endpoint row & Run Button
        row2 = ctk.CTkFrame(self.ai_body, fg_color="transparent")
        row2.pack(fill="x", padx=16, pady=(0, 12))

        col_ep = ctk.CTkFrame(row2, fg_color="transparent")
        col_ep.pack(side="left", fill="x", expand=True, padx=(0, 10))
        ctk.CTkLabel(col_ep, text="API Endpoint URL", font=get_font(11)).pack(anchor="w")
        self.ai_endpoint_entry = ctk.CTkEntry(col_ep, height=34)
        self.ai_endpoint_entry.insert(0, "http://localhost:11434/v1/chat/completions")
        self.ai_endpoint_entry.pack(fill="x", pady=(3, 0))

        self.ai_run_btn = ctk.CTkButton(
            row2,
            text="🚀 Run AI Audit",
            font=get_font(12, "bold"),
            fg_color=ACCENT_PRIMARY,
            hover_color=ACCENT_HOVER,
            text_color="#000000",
            width=130,
            height=34,
            command=self._start_ai_audit,
        )
        self.ai_run_btn.pack(side="right", pady=(18, 0))

        # AI Output Container
        self.ai_output_frame = ctk.CTkFrame(self.ai_body, fg_color=BG_INPUT, corner_radius=8)

    def _toggle_ai_panel(self) -> None:
        self._ai_expanded = not self._ai_expanded
        if self._ai_expanded:
            self.ai_body.pack(fill="x", pady=(0, 8))
            self.ai_expand_btn.configure(text="▲ Hide Settings")
        else:
            self.ai_body.pack_forget()
            self.ai_expand_btn.configure(text="▼ Configure & Scan")

    def _on_ai_provider_changed(self, provider_display_name: str) -> None:
        prov_key = self.provider_key_map.get(provider_display_name, "ollama")
        meta = AI_PROVIDERS.get(prov_key, AI_PROVIDERS["ollama"])

        self.ai_endpoint_entry.delete(0, "end")
        self.ai_endpoint_entry.insert(0, meta["default_endpoint"])

        self.ai_model_entry.delete(0, "end")
        self.ai_model_entry.insert(0, meta["default_model"])

    def _start_ai_audit(self) -> None:
        if self._ai_scanning:
            return

        self._ai_scanning = True
        self.ai_run_btn.configure(state="disabled", text="Analyzing...")
        self.status_banner.configure(text="Running AI security audit in background...", text_color=COLOR_WARNING)

        prov_name = self.ai_provider_combo.get()
        prov_key = self.provider_key_map.get(prov_name, "ollama")
        model = self.ai_model_entry.get().strip()
        key = self.ai_key_entry.get().strip()
        endpoint = self.ai_endpoint_entry.get().strip()

        entries = self.database.get_all_entries(self.encryption_key)

        def worker():
            try:
                advisor = AIAdvisor(provider=prov_key, api_key=key, model=model, endpoint=endpoint)
                result = advisor.analyze_vault(entries)
                self.after(0, lambda: self._on_ai_audit_complete(result, None))
            except Exception as ex:
                self.after(0, lambda: self._on_ai_audit_complete(None, str(ex)))

        threading.Thread(target=worker, daemon=True).start()

    def _on_ai_audit_complete(self, result: Optional[AIAnalysisResult], error: Optional[str]) -> None:
        self._ai_scanning = False
        self.ai_run_btn.configure(state="normal", text="🚀 Run AI Audit")

        if error:
            self.status_banner.configure(text=f"AI Audit Error: {error}", text_color=COLOR_DANGER)
            return

        self.ai_result = result
        self.status_banner.configure(text="✓ AI Security Audit complete!", text_color=COLOR_SUCCESS)
        self._render_ai_results(result)

    def _render_ai_results(self, result: AIAnalysisResult) -> None:
        self.ai_output_frame.pack(fill="x", padx=16, pady=(8, 16))
        for child in self.ai_output_frame.winfo_children():
            child.destroy()

        ctk.CTkLabel(
            self.ai_output_frame,
            text=f"AI Assessment: {result.summary}",
            font=get_font(12, "bold"),
            text_color=TEXT_PRIMARY,
            wraplength=600,
            justify="left",
        ).pack(anchor="w", padx=14, pady=(12, 6))

        if result.findings:
            f_frame = ctk.CTkFrame(self.ai_output_frame, fg_color="transparent")
            f_frame.pack(fill="x", padx=14, pady=4)
            for f in result.findings:
                ctk.CTkLabel(
                    f_frame,
                    text=f"• {f}",
                    font=get_font(11),
                    text_color=TEXT_SECONDARY,
                    wraplength=580,
                    justify="left",
                ).pack(anchor="w", pady=1)

        if result.actions:
            ctk.CTkLabel(
                self.ai_output_frame,
                text="Recommended AI Actions:",
                font=get_font(11, "bold"),
                text_color=ACCENT_PRIMARY,
            ).pack(anchor="w", padx=14, pady=(8, 4))

            for act in result.actions:
                act_row = ctk.CTkFrame(self.ai_output_frame, fg_color=BG_CARD, corner_radius=6)
                act_row.pack(fill="x", padx=14, pady=3)

                ctk.CTkLabel(
                    act_row,
                    text=f"[{act.action_type.upper()}] '{act.entry_title}': {act.reason}",
                    font=get_font(11),
                    text_color=TEXT_PRIMARY,
                    wraplength=480,
                    justify="left",
                ).pack(side="left", padx=10, pady=6)

                if self.on_review_entry and act.entry_id:
                    ctk.CTkButton(
                        act_row,
                        text="Review",
                        font=get_font(10, "bold"),
                        width=70,
                        height=24,
                        fg_color=BG_INPUT,
                        hover_color=BORDER_COLOR,
                        command=lambda eid=act.entry_id: self.on_review_entry(eid),
                    ).pack(side="right", padx=6)

                if act.action_type in ("set_category", "update_tags", "normalize_title", "merge_duplicate", "purge_ghost"):
                    ctk.CTkButton(
                        act_row,
                        text="⚡ Apply",
                        font=get_font(10, "bold"),
                        width=70,
                        height=24,
                        fg_color=COLOR_SUCCESS,
                        hover_color=ACCENT_HOVER,
                        text_color="#000000",
                        command=lambda a=act: self._handle_apply_ai_action(a),
                    ).pack(side="right", padx=4)

    def refresh(self) -> None:
        """Performs in-memory audit of all decrypted entries and updates UI."""
        entries = self.database.get_all_entries(self.encryption_key)
        advisor = VaultHealthAdvisor()
        self.report = advisor.analyze(entries)
        self._render_report(self.report)

    def _render_report(self, report: VaultHealthReport) -> None:
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

        # 2. Expiry alert banner
        if report.expiring_keys_count > 0:
            self.expiry_alert_lbl.configure(
                text=f"⚠️ ATTENTION: {report.expiring_keys_count} credential(s) or API key(s) have expired or expire soon! Review and auto-extend them below."
            )
            self.expiry_alert_frame.pack(fill="x", pady=(0, 14))
        else:
            self.expiry_alert_frame.pack_forget()

        # 3. Rebuild issues list
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

    def _create_metric_pill(self, parent, label: str, count: int, color: str) -> None:
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

    def _render_issue_card(self, issue: HealthIssue) -> None:
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

        # Action Buttons on right: Auto-Fix and Review
        btn_box = ctk.CTkFrame(header, fg_color="transparent")
        btn_box.pack(side="right")

        # ⚡ Auto-Fix Button (One-click remediation!)
        if issue.remediation_action:
            ctk.CTkButton(
                btn_box,
                text="⚡ Auto-Fix",
                font=get_font(11, "bold"),
                width=95,
                height=28,
                fg_color=COLOR_SUCCESS,
                hover_color=ACCENT_HOVER,
                text_color="#000000",
                command=lambda iss=issue: self._handle_auto_fix(iss),
            ).pack(side="left", padx=4)

        if self.on_review_entry and issue.entry_ids:
            for idx, entry_id in enumerate(issue.entry_ids[:1]):
                title = issue.entry_titles[idx] if idx < len(issue.entry_titles) else "Entry"
                short_title = (title[:14] + "..") if len(title) > 14 else title
                ctk.CTkButton(
                    btn_box,
                    text=f"Review '{short_title}'",
                    font=get_font(11),
                    width=110,
                    height=28,
                    fg_color=BG_INPUT,
                    hover_color=BORDER_COLOR,
                    text_color=TEXT_PRIMARY,
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

    def _handle_auto_fix(self, issue: HealthIssue) -> None:
        success, msg = fix_health_issue(issue, self.database, self.encryption_key)
        if success:
            self._notify_update(f"✓ Auto-Fix Applied: {msg}")
        else:
            self.status_banner.configure(text=f"Auto-Fix Error: {msg}", text_color=COLOR_DANGER)

    def _notify_update(self, message: str, is_error: bool = False) -> None:
        color = COLOR_DANGER if is_error else COLOR_SUCCESS
        self.status_banner.configure(text=message, text_color=color)
        self.refresh()
        if self.on_vault_updated:
            try:
                self.on_vault_updated()
            except Exception:
                pass

    def _handle_auto_organize_all(self) -> None:
        summary = auto_organize_vault(self.database, self.encryption_key, override_categories=False)
        self._notify_update(
            f"✓ Auto-Organized Vault: {summary.categories_updated} categories assigned, "
            f"{summary.tags_added} tags enriched, {summary.titles_normalized} titles normalized."
        )

    def _handle_auto_group(self) -> None:
        summary = auto_organize_vault(self.database, self.encryption_key, override_categories=True)
        self._notify_update(f"✓ Auto-Group complete: {summary.categories_updated} categories assigned.")

    def _handle_auto_tag(self) -> None:
        summary = auto_organize_vault(self.database, self.encryption_key, override_categories=False)
        self._notify_update(f"✓ Auto-Tag complete: {summary.tags_added} smart tags added across entries.")

    def _handle_merge_duplicates(self) -> None:
        res = deduplicate_vault(self.database, self.encryption_key, auto_merge=True)
        if res["merged_count"] > 0:
            self._notify_update(f"✓ Merged {res['merged_count']} redundant duplicate entries into primary records.")
        else:
            self.status_banner.configure(text="No duplicate entry clusters detected.", text_color=TEXT_MUTED)

    def _handle_purge_ghosts(self) -> None:
        res = purge_ghost_entries(self.database, self.encryption_key)
        self._notify_update(f"✓ Cleaned: purged {res['purged_ghosts']} empty records and repaired {res['fixed_orphans']} orphan references.")

    def _handle_auto_organize_files(self) -> None:
        res = auto_organize_files(self.database, self.encryption_key)
        self._notify_update(f"✓ Auto-Organized Files: {res['files_updated']} vault attachments tagged and filed by type.")

    def _handle_apply_sort(self) -> None:
        choice = self.sort_combo.get()
        mapping = {
            "Category (A-Z)": "category",
            "Title (A-Z)": "title_asc",
            "Title (Z-A)": "title_desc",
            "Security Risk (Weakest First)": "risk",
            "Recency (Modified First)": "recency",
            "Type (Servers -> Keys)": "type",
        }
        strategy = mapping.get(choice, "category")
        entries = self.database.get_all_entries(self.encryption_key)
        sorted_list = sort_entries(entries, sort_by=strategy)
        self._notify_update(f"✓ Auto-sorted {len(sorted_list)} entries by {choice}.")

    def _handle_apply_ai_action(self, action: AIRemediationAction) -> None:
        entry = self.database.get_entry(action.entry_id, self.encryption_key)
        if not entry:
            self._notify_update("Target entry not found.", is_error=True)
            return

        if action.action_type == "set_category" and action.suggested_value:
            entry.category = action.suggested_value
            self.database.save_entry(entry, self.encryption_key)
            self._notify_update(f"✓ Set category for '{entry.title}' to [{action.suggested_value}].")

        elif action.action_type == "update_tags" and action.suggested_value:
            tags_to_add = [t.strip().lower() for t in action.suggested_value.split(",") if t.strip()]
            cur_tags = set(entry.tags)
            cur_tags.update(tags_to_add)
            entry.tags = sorted(list(cur_tags))
            self.database.save_entry(entry, self.encryption_key)
            self._notify_update(f"✓ Updated tags for '{entry.title}'.")

        elif action.action_type == "normalize_title" and action.suggested_value:
            entry.title = action.suggested_value
            self.database.save_entry(entry, self.encryption_key)
            self._notify_update(f"✓ Normalized title to '{entry.title}'.")

        elif action.action_type == "merge_duplicate":
            res = deduplicate_vault(self.database, self.encryption_key, auto_merge=True)
            self._notify_update(f"✓ Merged {res['merged_count']} duplicates.")

        elif action.action_type == "purge_ghost":
            self.database.delete_entry(action.entry_id)
            self._notify_update(f"✓ Purged ghost entry '{entry.title}'.")

