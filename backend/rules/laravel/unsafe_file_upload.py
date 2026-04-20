"""
Unsafe File Upload Rule

Detects common unsafe file upload patterns, such as:
  $request->file('x')->move(...)
  $request->file('x')->store(...)

This is heuristic-based and uses AST-extracted call sites and derived validation metrics.
"""
from schemas.facts import Facts, MethodInfo
from schemas.metrics import MethodMetrics
from schemas.finding import Finding, Category, Severity
from rules.base import Rule


class UnsafeFileUploadRule(Rule):
    id = "unsafe-file-upload"
    name = "Unsafe File Upload"
    description = "Detects file upload handling without validation"
    category = Category.SECURITY
    default_severity = Severity.HIGH
    applicable_project_types = [
        "laravel_blade",
        "laravel_inertia_react",
        "laravel_inertia_vue",
        "laravel_api",
        "laravel_livewire",
    ]
    _SVG_RULE_SIGNAL = ("mimes:svg", "mimetypes:image/svg+xml", "image/svg+xml", "svg")
    _SVG_SANITIZE_SIGNAL = ("sanitizesvg", "sanitize_svg", "svgsanitizer", "dompurify")
    _ORIGINAL_NAME_SIGNAL = ("getclientoriginalname(", "getclientoriginalextension(")
    _FILENAME_GUARD_SIGNAL = ("pathinfo(", "basename(", "str_replace('..", "preg_match(")

    def analyze(
        self,
        facts: Facts,
        metrics: dict[str, MethodMetrics] | None = None,
    ) -> list[Finding]:
        findings: list[Finding] = []

        for m in facts.methods:
            if not m.call_sites:
                continue

            lc_sites = [c.lower() for c in m.call_sites]
            has_file_access = any("->file(" in c or "->hasfile(" in c for c in lc_sites)
            has_store = any("->store(" in c or "->storeas(" in c or "->move(" in c for c in lc_sites)
            if not (has_file_access and has_store):
                continue

            has_validation = False
            if metrics and m.method_fqn in metrics:
                has_validation = bool(metrics[m.method_fqn].has_validation)
            else:
                # Fallback: cheap heuristic from call sites.
                has_validation = any("->validate(" in c or "validator::" in c or "validated(" in c for c in lc_sites)

            if has_validation:
                # Still potentially risky, but we only flag the "no validation" case by default.
                pass
            else:
                ctx = m.method_fqn
                findings.append(
                    self.create_finding(
                        title="File upload without validation",
                        context=ctx,
                        file=m.file_path,
                        line_start=m.line_start,
                        line_end=m.line_end,
                        description=(
                            "Detected file upload handling (`file()` + `move()`/`store()`) without any validation in this method. "
                            "Uploads should be validated for type and size."
                        ),
                        why_it_matters=(
                            "Unsafe uploads can lead to security vulnerabilities (malicious files, storage exhaustion, "
                            "and in some setups even remote code execution). Validation and safe storage APIs reduce risk."
                        ),
                        suggested_fix=(
                            "1. Validate uploads with rules like: `required|file|mimes:jpg,png,pdf|max:2048`\n"
                            "2. Prefer `Storage::putFile` / `$file->store()` over manual `move()`\n"
                            "3. Store outside the public web root and serve via signed URLs when needed\n"
                            "4. Generate random filenames and avoid trusting client-provided names"
                        ),
                        code_example=(
                            "// Before\n"
                            "$request->file('avatar')->move(public_path('uploads'), $name);\n\n"
                            "// After\n"
                            "$request->validate(['avatar' => 'required|file|mimes:jpg,png|max:2048']);\n"
                            "$path = $request->file('avatar')->store('avatars');\n"
                        ),
                        tags=["security", "uploads", "validation", "laravel"],
                        confidence=0.65,
                    )
                )

            # Sub-detector: svg-upload-xss-risk
            has_svg_signal = any(any(sig in c for sig in self._SVG_RULE_SIGNAL) for c in lc_sites)
            has_sanitize_signal = any(any(sig in c for sig in self._SVG_SANITIZE_SIGNAL) for c in lc_sites)
            if has_svg_signal and not has_sanitize_signal:
                findings.append(
                    self.create_finding(
                        title="SVG upload may allow script payloads",
                        context=m.method_fqn,
                        file=m.file_path,
                        line_start=m.line_start,
                        line_end=m.line_end,
                        description=(
                            "Detected SVG upload handling without visible sanitization safeguards."
                        ),
                        why_it_matters="SVG files can embed script payloads and become stored-XSS vectors when served directly.",
                        suggested_fix=(
                            "Disallow SVG uploads by default, or sanitize SVG content before storage/serving."
                        ),
                        tags=["security", "uploads", "svg", "xss"],
                        confidence=0.82,
                        metadata={"upload_subcontext": "svg-upload-xss-risk"},
                    )
                )

            # Sub-detector: double-extension-upload
            uses_original_name = any(any(sig in c for sig in self._ORIGINAL_NAME_SIGNAL) for c in lc_sites)
            has_filename_guard = any(any(sig in c for sig in self._FILENAME_GUARD_SIGNAL) for c in lc_sites)
            if uses_original_name and not has_filename_guard:
                findings.append(
                    self.create_finding(
                        title="Upload flow may trust untrusted client filename",
                        context=m.method_fqn,
                        file=m.file_path,
                        line_start=m.line_start,
                        line_end=m.line_end,
                        description=(
                            "Detected use of original client filenames without visible extension/basename normalization."
                        ),
                        why_it_matters=(
                            "Double-extension filenames (for example `invoice.pdf.php`) can bypass weak extension checks."
                        ),
                        suggested_fix=(
                            "Ignore original filenames for storage paths and generate safe server-side filenames."
                        ),
                        tags=["security", "uploads", "filename", "double-extension"],
                        confidence=0.8,
                        metadata={"upload_subcontext": "double-extension-upload"},
                    )
                )

        return findings
