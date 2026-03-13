"""
React Hardcoded User Facing Strings Rule

Detects likely user-facing UI text that is hardcoded instead of going through i18n helpers.
"""

from __future__ import annotations

import re

from schemas.facts import Facts
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class HardcodedUserFacingStringsRule(Rule):
    id = "hardcoded-user-facing-strings"
    name = "Hardcoded User Facing Strings"
    description = "Detects likely user-facing hardcoded strings not wrapped in i18n"
    category = Category.REACT_BEST_PRACTICE
    default_severity = Severity.MEDIUM
    type = "regex"
    applicable_project_types: list[str] = []
    regex_file_extensions = [".js", ".jsx", ".ts", ".tsx"]

    _ATTR_PATTERN = re.compile(
        r"\b(placeholder|title|aria-label|alt|label)\s*=\s*['\"]([^'\"{}][^'\"]{1,})['\"]",
        re.IGNORECASE,
    )
    _JSX_TEXT_PATTERN = re.compile(r">\s*([A-Za-z][A-Za-z0-9 ,.!?'\\-]{2,})\s*<\s*/")
    _I18N_HINTS = ("t(", "i18n.", "<Trans", "intl.", "formatMessage(")
    _ALLOWLIST_PATH_MARKERS = (
        "/tests/",
        "/test/",
        "/__tests__/",
        "/stories/",
        "/storybook/",
        "/demo/",
        "/demos/",
        "/fixtures/",
        "/locales/",
        "/i18n/",
        "/translations/",
        "/generated/",
        "/dist/",
        "/build/",
    )
    _ATTR_ALLOWLIST = {"data-testid", "id", "name", "value", "className"}
    
    # Proper nouns (brand names, company names) - don't require translation
    _PROPER_NOUN_ALLOWLIST = {
        # Payment/SMS providers
        "twilio", "meta", "stripe", "paymob", "hypersender",
        # Tech companies
        "google", "facebook", "apple", "microsoft", "amazon", "aws", "azure",
        "openai", "anthropic", "vercel", "netlify", "heroku",
        # Common SaaS tools
        "slack", "discord", "notion", "figma", "jira", "github", "gitlab",
        "bitbucket", "docker", "kubernetes", "nginx",
        # Communication platforms
        "whatsapp", "telegram", "signal", "viber", "messenger",
        # Database/infrastructure
        "mysql", "postgresql", "postgres", "mongodb", "redis", "elasticsearch",
        "firebase", "supabase",
    }
    
    # Technical terms that don't require translation
    _TECHNICAL_TERMS = {
        "tls", "ssl", "ssh", "ftp", "http", "https", "api", "rest", "graphql",
        "json", "xml", "yaml", "csv", "html", "css", "sql",
        "smtp", "imap", "pop3", "tcp", "udp", "dns", "cdn",
        "oauth", "jwt", "saml", "openid",
        "ios", "android", "windows", "macos", "linux", "ubuntu",
        "none", "null", "undefined", "nan",
    }
    _SINGLE_WORD_LABEL_ALLOWLIST = {
        "save",
        "cancel",
        "edit",
        "delete",
        "close",
        "open",
        "next",
        "back",
        "search",
        "filter",
        "clear",
        "submit",
        "reset",
        "continue",
        "dashboard",
        "settings",
        "profile",
        "home",
        "login",
        "logout",
        "email",
        "phone",
        "name",
        "status",
        "type",
        "role",
        "admin",
        "portal",
    }

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        return []

    def analyze_regex(
        self,
        file_path: str,
        content: str,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        if self._is_allowlisted_path(file_path):
            return []

        findings: list[Finding] = []
        lines = content.splitlines()

        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith(("import ", "export ", "//", "/*", "*")):
                continue
            if any(h in line for h in self._I18N_HINTS):
                continue
            if "<" not in line and not any(a in line for a in ["placeholder=", "title=", "aria-label=", "alt=", "label="]):
                continue

            matches: list[str] = []
            evidence: list[str] = []

            for m in self._ATTR_PATTERN.finditer(line):
                attr = str(m.group(1) or "").strip()
                if attr in self._ATTR_ALLOWLIST:
                    continue
                txt = (m.group(2) or "").strip()
                if self._looks_user_facing(txt):
                    matches.append(txt)
                    evidence.append(f"jsx_attr={attr}")

            for m in self._JSX_TEXT_PATTERN.finditer(line):
                txt = (m.group(1) or "").strip()
                if self._looks_user_facing(txt):
                    matches.append(txt)
                    evidence.append("jsx_text_literal")

            if not matches:
                continue

            for txt, ev in zip(matches, evidence):
                sample = txt
                if len(sample) > 80:
                    sample = sample[:77] + "..."

                findings.append(
                    self.create_finding(
                        title="Likely user-facing string is hardcoded",
                        context=f"text:{txt[:50]}", # Stable fingerprint based on CONTENT, not line
                        file=file_path,
                        line_start=i,
                        description=(
                            f"Detected hardcoded UI text (`{sample}`) that does not appear to use an i18n helper."
                        ),
                        why_it_matters=(
                            "Hardcoded UI strings make localization expensive and inconsistent across the product."
                        ),
                        suggested_fix=(
                            "Wrap user-facing strings with your i18n helper (e.g. `t('...')`) and centralize keys "
                            "in locale files."
                        ),
                        tags=["react", "i18n", "localization", "maintainability"],
                        confidence=0.72 if ev.startswith("jsx_attr=") else 0.66,
                        evidence_signals=[
                            f"file={file_path}",
                            f"line={i}",
                            ev,
                        ],
                    )
                )

        if not findings:
            return []

        # Aggregate into a single finding for the file to reduce noise
        first = findings[0]
        count = len(findings)
        
        # Collect distinct bad strings for the description
        distinct_samples = sorted({f.description.split("(`")[1].split("`)")[0] for f in findings})
        sample_text = ", ".join(f"`{s}`" for s in distinct_samples[:3])
        if len(distinct_samples) > 3:
            sample_text += f", and {len(distinct_samples) - 3} more"

        # Collect all line numbers
        lines = sorted({f.line_start for f in findings})
        lines_str = ", ".join(str(l) for l in lines)

        aggregated_finding = self.create_finding(
            title=f"Likely user-facing strings are hardcoded ({count} matches)",
            context=f"file:{file_path}", # File-level fingerprint
            file=file_path,
            line_start=lines[0],
            description=(
                f"Detected {count} hardcoded user-facing strings in this file that do not appear to use an i18n helper.\n"
                f"Strings: {sample_text}."
            ),
            why_it_matters=(
                "Hardcoded UI strings make localization expensive and inconsistent across the product."
            ),
            suggested_fix=(
                "Wrap these strings with your i18n helper (e.g. `t('...')`) and centralize keys in locale files."
            ),
            tags=["react", "i18n", "localization", "maintainability"],
            confidence=0.72, # A bit lower since it's an aggregate
            evidence_signals=[
                f"file={file_path}",
                f"count={count}",
                f"lines={lines_str}",
            ]
        )
        
        # Add detailed evidence for each match
        for f in findings:
             aggregated_finding.evidence_signals.append(f"match_line={f.line_start}: {f.context}")

        return [aggregated_finding]

    def _is_allowlisted_path(self, file_path: str) -> bool:
        low = (file_path or "").lower().replace("\\", "/")
        return any(marker in low for marker in self._ALLOWLIST_PATH_MARKERS)

    def _looks_user_facing(self, txt: str) -> bool:
        s = (txt or "").strip()
        if len(s) < 3:
            return False
        low = s.lower()
        if re.fullmatch(r"[a-z0-9_.-]+", low) and ("." in low or "_" in low):
            # likely a key-like token (i18n/config/etc), not rendered prose.
            return False
        if re.fullmatch(r"[A-Za-z0-9_:-]+", s) and " " not in s and s.lower() == s:
            return False
        if low.startswith(("http://", "https://", "/", "./", "../")):
            return False
        if any(token in low for token in ["px", "rem", "vh", "vw", "class-", "bg-", "text-", "flex", "grid"]):
            return False
        if re.fullmatch(r"[A-Z0-9_\\-]+", s):
            return False
        if re.search(r"\b(testid|data-testid|classname|onClick|onChange|router\.)\b", s):
            return False
        
        # Skip proper nouns (brand names, company names)
        if low in self._PROPER_NOUN_ALLOWLIST:
            return False
        # Skip technical terms that don't require translation
        if low in self._TECHNICAL_TERMS:
            return False
        # Skip if it's a single capitalized word that matches a proper noun
        if s[0].isupper() and s[1:].islower() and low in self._PROPER_NOUN_ALLOWLIST:
            return False
        if " " not in s and not re.search(r"[,.!?/:;]", s):
            if low in self._SINGLE_WORD_LABEL_ALLOWLIST:
                return False
            if s[0].isupper() and s[1:].islower() and len(s) <= 10:
                return False
        
        letters = sum(1 for c in s if c.isalpha())
        return letters >= 2
