# Accessibility Fixes Implementation Checklist

## Project Status: Ready for Implementation

### How to Use This Checklist

1. Copy `scripts/apply-a11y-fixes.sh` to your Laravel project root
2. Run: `bash apply-a11y-fixes.sh`
3. Complete manual fixes listed below
4. Run test suite: `npm test`
5. Re-scan with BestPracticesDoctor

---

## Phase 1: Automated Fixes (Run Script) ⏱️ 15 min

- [ ] **1. Install focus-trap-react**: `npm install focus-trap-react`
- [ ] **2. Run automated script**: `bash apply-a11y-fixes.sh`
  - [ ] Color contrast (gray-400 → gray-600)
  - [ ] Autocomplete attributes added
  - [ ] ARIA live regions for alerts
  - [ ] Focus indicators for hover-only buttons

---

## Phase 2: Manual Core Fixes ⏱️ 30 min

### 2.1 Modal Focus Trap (HIGH PRIORITY)

**File:** `resources/js/components/UI/Modal.tsx`

**Action:** Wrap modal content with FocusTrap or add manual focus trap

**Option A - With Library (Recommended):**
```tsx
import FocusTrap from "focus-trap-react";

return createPortal(
  <FocusTrap>
    <div role="dialog" aria-modal="true">...</div>
  </FocusTrap>,
  document.body
);
```

**Option B - Manual Implementation:**
See `accessibility_fixes_batch_2.md` for complete manual implementation

**Test:**
- [ ] Tab cycles within modal
- [ ] Shift+Tab cycles backwards
- [ ] Escape closes modal
- [ ] Focus returns to trigger button on close

### 2.2 Skip Links (HIGH PRIORITY)

**Files:**
- `resources/js/layouts/AuthenticatedLayout.tsx`
- `resources/js/layouts/PatientPortalLayout.tsx`

**Action:** Add skip link after opening `<div>`:

```tsx
<a
  href="#main-content"
  className="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-50 focus:px-4 focus:py-2 focus:bg-primary focus:text-white focus:rounded-md"
>
  Skip to main content
</a>
```

**Also add:** `id="main-content"` to `<main>` element

**Test:**
- [ ] Press Tab on page load - skip link appears
- [ ] Click skip link - focus moves to main content
- [ ] Screen reader announces skip link

---

## Phase 3: Component-Level Fixes ⏱️ 45 min

### 3.1 Status Messages (17 files)

**Pattern:** Wrap flash/notification elements with `role="status"`

```diff
- {flash?.success && <div className="alert alert-success">{flash.success}</div>}
+ {flash?.success && (
+   <div role="status" aria-live="polite" className="alert alert-success">
+     {flash.success}
+   </div>
+ )}

- {flash?.error && <div className="alert alert-error">{flash.error}</div>}
+ {flash?.error && (
+   <div role="alert" aria-live="assertive" className="alert alert-error">
+     {flash.error}
+   </div>
+ )}
```

**Files to update:**
- [ ] `resources/js/layouts/AuthenticatedLayout.tsx`
- [ ] `resources/js/layouts/GuestLayout.tsx`
- [ ] `resources/js/pages/Appointments/Index.tsx`
- [ ] `resources/js/pages/Clinic/Campaigns/Index.tsx`
- [ ] `resources/js/pages/Clinic/Insurance/Claims/Index.tsx`
- [ ] `resources/js/pages/Clinic/Inventory/Counts/Index.tsx`
- [ ] `resources/js/pages/Clinic/Inventory/Index.tsx`
- [ ] `resources/js/pages/Clinic/Inventory/Transfers/Index.tsx`
- [ ] `resources/js/pages/Clinic/Lab/Orders/Index.tsx`
- [ ] `resources/js/pages/Clinic/Settings/CommunicationTemplatesSettingsContent.tsx`
- [ ] `resources/js/pages/Clinic/Waitlist/Index.tsx`
- [ ] `resources/js/pages/Portal/Billing/Index.tsx`
- [ ] `resources/js/pages/Portal/ClientErrorReports/Show.tsx`
- [ ] `resources/js/pages/Portal/Clinics/IndexView.tsx`
- [ ] `resources/js/pages/Portal/FeatureMatrix/Index.tsx`

### 3.2 Error Message Associations (3 files)

**Pattern:** Add `aria-errormessage` to inputs

```diff
  <input
    id="field-id"
    {...field}
+   aria-invalid={errors.field ? "true" : "false"}
+   aria-errormessage="field-error"
  />
  {errors.field && (
-   <p className="text-red-500">{errors.field}</p>
+   <p id="field-error" className="text-red-500" role="alert">
+     {errors.field}
+   </p>
  )}
```

**Files:**
- [ ] `resources/js/pages/Clinic/Settings/Branding/BrandingCropModal.tsx`
- [ ] `resources/js/pages/Clinic/Surveys/Create.tsx`
- [ ] `resources/js/pages/Portal/Settings/Index.tsx`

### 3.3 Heading Order (4 files)

**Pattern:** Change h3 to h2 OR add sr-only h2

```diff
  <section>
-   <h3>Section Title</h3>
+   <h2 className="text-xl font-semibold">Section Title</h2>
  </section>
```

**OR if visual hierarchy must stay:**
```diff
  <section>
+   <h2 className="sr-only">Section Overview</h2>
    <h3>Section Title</h3>
  </section>
```

**Files:**
- [ ] `resources/js/pages/Admin/Reports/Dashboard.tsx`
- [ ] `resources/js/pages/Admin/Webhooks/Index.tsx`
- [ ] `resources/js/pages/Patients/Show.tsx`
- [ ] `resources/js/pages/Portal/Clinics/ShowView.tsx`

---

## Phase 4: Polish ⏱️ 15 min

### 4.1 Button Text (4 files)

**Pattern:** Make button text descriptive OR add `aria-label`

```diff
- <button onClick={handleSubmit}>Submit</button>
+ <button onClick={handleSubmit} aria-label="Save medical history">
+   Save Medical History
+ </button>
```

**Files:**
- [ ] `resources/js/pages/Patients/MedicalHistoryFormContainer/Index.tsx`
- [ ] `resources/js/pages/Profile/EditView.tsx` (2 occurrences)
- [ ] `resources/js/pages/Services/Create.tsx`

### 4.2 Focus Indicator (1 file)

**File:** `resources/js/pages/Admin/Communication/Templates/Index.tsx`

```diff
- <button className="... hover:bg-amber-200">
+ <button className="... hover:bg-amber-200 focus:ring-2 focus:ring-amber-400 focus:outline-none">
```

---

## Verification ⏱️ 15 min

### Automated Testing
- [ ] Run unit tests: `npm test`
- [ ] Build project: `npm run build`
- [ ] No console errors
- [ ] No TypeScript errors: `npx tsc --noEmit`

### Manual Accessibility Testing
- [ ] Keyboard navigation works (Tab, Shift+Tab, Enter, Escape)
- [ ] Skip link visible and functional
- [ ] Modal traps focus
- [ ] Error messages announced by screen reader
- [ ] Status messages announced without stealing focus

### Tool Verification
- [ ] Run axe DevTools - 0 critical issues
- [ ] Run WAVE - 0 errors
- [ ] Verify contrast with WebAIM tool (all text ≥ 4.5:1)
- [ ] Re-run BestPracticesDoctor scan - verify findings reduced

---

## Expected Results

| Category | Before | After | Reduction |
|----------|--------|-------|-----------|
| modal-trap-focus | 27 | 0 | 100% |
| color-contrast-ratio | 6 | 0 | 100% |
| status-message-announcement | 17 | 0 | 100% |
| autocomplete-missing | 29 | 0 | 100% |
| heading-order | 4 | 0 | 100% |
| error-message-missing | 3 | 0 | 100% |
| button-text-vague | 4 | 0 | 100% |
| focus-indicator-missing | 1 | 0 | 100% |
| **TOTAL** | **91** | **0** | **100%** |

---

## Time Estimate

- Automated fixes: 15 min
- Manual fixes: 90 min
- Testing: 15 min
- **Total: ~2 hours**

## Resources

- **Patch document:** `accessibility_fixes_batch_2.md`
- **Automation script:** `scripts/apply-a11y-fixes.sh`
- **Codemod:** `scripts/accessibility-codemod.ts` (for jscodeshift)
- **WCAG Guidelines:** https://www.w3.org/WAI/WCAG21/quickref/
- **Contrast Checker:** https://webaim.org/resources/contrastchecker/

---

## Post-Implementation

After completing all fixes:

1. Commit changes: `git commit -m "fix(accessibility): resolve 91 a11y findings"`
2. Create PR with before/after scan results
3. Schedule quarterly accessibility audits
4. Add a11y linting to CI: `npm install eslint-plugin-jsx-a11y --save-dev`

---

**Questions or issues?** Refer to the detailed patch document or run the automated script with `--dry-run` flag first.
