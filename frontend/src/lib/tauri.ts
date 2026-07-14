
export function isTauriRuntime(): boolean {
    const w = window as unknown as { __TAURI_INTERNALS__?: Record<string, unknown> } | undefined;
    return !!(w && w.__TAURI_INTERNALS__);
}
