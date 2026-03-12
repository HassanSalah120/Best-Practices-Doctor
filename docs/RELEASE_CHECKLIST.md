# Release Checklist

This checklist is for v1.0 release hardening. Keep changes small and avoid refactors.

## Gates

### 1) Windows Path Edge Cases

- Ensure `facts.files` are normalized to forward slashes (`/`).
- Ensure regex rules gate on normalized paths (avoid `\\` vs `/` mismatches).

### 2) Performance

- Run backend tests including performance:

```powershell
Set-Location .\backend
python -m pytest -q
```

### 3) UI Scoring Clarity

- If a category weight is 0 in ruleset weights, UI must show `N/A` (not `0%`).

### 4) Packaging Smoke Test (Windows)

From repo root:

```powershell
.\dev.ps1
```

Then:

- Run a scan on a real Laravel repo with `vendor/` present to confirm ignore globs and performance.
- Confirm sidecar starts reliably (no discovery failures).

Optional build smoke:

```powershell
Set-Location .\tauri
npm run tauri build
```

## Common Issues

### Vite port already in use (1420)

Stop the existing Vite process, then re-run `.\dev.ps1`.

