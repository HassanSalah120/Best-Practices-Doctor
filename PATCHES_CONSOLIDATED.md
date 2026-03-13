# Accessibility Fixes - Consolidated Patches

## Summary

| Category | Count | Status | Action |
|----------|-------|--------|--------|
| modal-trap-focus | 27 | TRUE | Fix core Modal.tsx |
| color-contrast-ratio | 6 | TRUE | Darken text colors |
| page-title-missing | 4 | FALSE | Rule fixed - excluded |
| touch-target-size | 68 | MIXED | Review individually |
| missing-usememo | 32 | MIXED | Review individually |
| status-message-announcement | 17 | TRUE | Add aria-live |
| error-message-missing | 3 | TRUE | Add aria-errormessage |
| heading-order | 1 | TRUE | Fix h4→h3 |
| autocomplete-missing | 29 | TRUE | Add autocomplete |
| button-text-vague | 4 | TRUE | Add aria-label |

**True Positives: 87 fixes needed**

---

## 1. MODAL FOCUS TRAP (27 files → 1 fix)

### Root Cause: Fix Core Modal Component

**File:** `resources/js/components/UI/Modal.tsx`

**Option A - With focus-trap-react (Recommended):**

```bash
npm install focus-trap-react
```

```tsx
import FocusTrap from "focus-trap-react";

// Wrap the modal content:
return createPortal(
  <FocusTrap>
    <div role="dialog" aria-modal="true" ...>
      {children}
    </div>
  </FocusTrap>,
  document.body
);
```

**Option B - Manual Implementation (No dependency):**

```tsx
const Modal = ({ open, onClose, children }) => {
  const contentRef = useRef<HTMLDivElement>(null);
  const previousFocus = useRef<HTMLElement | null>(null);

  useEffect(() => {
    if (open) {
      previousFocus.current = document.activeElement as HTMLElement;
      document.body.style.overflow = "hidden";
      // Focus first focusable element
      const focusable = contentRef.current?.querySelectorAll(
        'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
      );
      if (focusable?.length) (focusable[0] as HTMLElement).focus();
    } else {
      document.body.style.overflow = "";
      previousFocus.current?.focus();
    }
  }, [open]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key !== "Tab") return;
    const focusable = contentRef.current?.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    if (!focusable?.length) return;
    const first = focusable[0] as HTMLElement;
    const last = focusable[focusable.length - 1] as HTMLElement;
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  };

  return createPortal(
    <div onKeyDown={handleKeyDown} role="dialog" aria-modal="true" ...>
      <div ref={contentRef}>{children}</div>
    </div>,
    document.body
  );
};
```

**Rationale:** WCAG 2.4.3 Focus Order - all 27 modals inherit from this component.

---

## 2. COLOR CONTRAST (6 files)

### Pattern: gray-400/slate-400 on white = 3.1:1 (fails) → gray-600 = 6.6:1 (passes)

**resources/js/components/Booking/BookingCard.tsx:76**
```diff
- <p className="text-gray-400">{description}</p>
+ <p className="text-gray-600">{description}</p>
```

**resources/js/components/Booking/ClinicInfoCard.tsx:25-27**
```diff
- <span className="text-gray-400">{label}</span>
+ <span className="text-gray-600">{label}</span>

- <p className="text-slate-400">{value}</p>
+ <p className="text-slate-600">{value}</p>

- <span className="text-gray-300">{meta}</span>
+ <span className="text-gray-500">{meta}</span>
```

**resources/js/pages/Financials/Invoice/InvoiceCreateForm.tsx:85**
```diff
- <p className="text-gray-400 text-sm">{helper}</p>
+ <p className="text-gray-600 text-sm">{helper}</p>
```

**resources/js/pages/PatientPortal/Invoices/Show.tsx:35**
```diff
- <span className="text-slate-400">{status}</span>
+ <span className="text-slate-600">{status}</span>
```

---

## 3. STATUS MESSAGE ANNOUNCEMENT (17 files)

### Pattern: Add `role="status" aria-live="polite"`

**resources/js/layouts/AuthenticatedLayout.tsx:16**
```diff
  {flash?.success && (
-   <div className="alert alert-success">{flash.success}</div>
+   <div role="status" aria-live="polite" className="alert alert-success">
+     {flash.success}
+   </div>
  )}
  {flash?.error && (
-   <div className="alert alert-error">{flash.error}</div>
+   <div role="alert" aria-live="assertive" className="alert alert-error">
+     {flash.error}
+   </div>
  )}
```

**Apply same pattern to:**
- `resources/js/layouts/GuestLayout.tsx:16`
- `resources/js/pages/Appointments/Index.tsx:52`
- `resources/js/pages/Clinic/Campaigns/Index.tsx:26`
- `resources/js/pages/Clinic/Insurance/Claims/Index.tsx:60`
- `resources/js/pages/Clinic/Inventory/Counts/Index.tsx:18`
- `resources/js/pages/Clinic/Inventory/Index.tsx:34`
- `resources/js/pages/Clinic/Inventory/Transfers/Index.tsx:26`
- `resources/js/pages/Clinic/Lab/Orders/Index.tsx:32`
- `resources/js/pages/Clinic/Settings/CommunicationTemplatesSettingsContent.tsx:12`
- `resources/js/pages/Clinic/Waitlist/Index.tsx:31`
- `resources/js/pages/Portal/Billing/Index.tsx:26`
- `resources/js/pages/Portal/ClientErrorReports/Show.tsx:51`
- `resources/js/pages/Portal/Clinics/IndexView.tsx:37`
- `resources/js/pages/Portal/FeatureMatrix/Index.tsx:29`
- `resources/js/components/UI/FormInput.tsx:7`
- `resources/js/components/UI/Input.tsx:30`

---

## 4. ERROR MESSAGE ASSOCIATION (3 files)

### Pattern: Add `aria-errormessage` and `role="alert"`

**resources/js/pages/Clinic/Settings/Branding/BrandingCropModal.tsx:43**
```diff
  <input
    id="crop-width"
    {...field}
+   aria-invalid={errors.cropWidth ? "true" : "false"}
+   aria-errormessage="crop-width-error"
  />
  {errors.cropWidth && (
-   <p className="text-red-500">{errors.cropWidth}</p>
+   <p id="crop-width-error" className="text-red-500" role="alert">
+     {errors.cropWidth}
+   </p>
  )}
```

**resources/js/pages/Clinic/Surveys/Create.tsx:99**
```diff
  <input
    id="survey-title"
    {...field}
+   aria-invalid={errors.title ? "true" : "false"}
+   aria-errormessage="survey-title-error"
  />
  {errors.title && (
-   <span className="error">{errors.title}</span>
+   <span id="survey-title-error" className="error" role="alert">
+     {errors.title}
+   </span>
  )}
```

**resources/js/pages/Portal/Settings/Index.tsx:95**
```diff
  <input
    id="setting-value"
    {...field}
+   aria-invalid={errors.value ? "true" : "false"}
+   aria-errormessage="setting-value-error"
  />
  {errors.value && (
-   <p className="text-red-500">{errors.value}</p>
+   <p id="setting-value-error" className="text-red-500" role="alert">
+     {errors.value}
+   </p>
  )}
```

---

## 5. HEADING ORDER (1 file)

**resources/js/pages/Patients/Show.tsx:486**
```diff
  <section>
-   <h4>Subsection</h4>
+   <h3>Subsection</h3>
  </section>
```

**Or if h3 is missing in document structure:**
```diff
  <section>
+   <h3 className="sr-only">Section Title</h3>
    <h4>Subsection</h4>
  </section>
```

---

## 6. AUTOCOMPLETE MISSING (29 fields in 17 files)

### Quick Reference Table

| Input Type | ID Contains | autoComplete Value |
|------------|-------------|-------------------|
| email | email | `email` |
| password | password | `current-password` |
| password | new, confirm | `new-password` |
| text | firstName, first_name | `given-name` |
| text | lastName, last_name | `family-name` |
| text | name (full) | `name` |
| tel | phone | `tel` |
| text | organization, clinic | `organization` |

### Key Files

**resources/js/pages/Auth/Login/Index.tsx:43**
```diff
  <input type="email" id="email"
+   autoComplete="email"
    {...field} />
  <input type="password" id="password"
+   autoComplete="current-password"
    {...field} />
```

**resources/js/pages/Auth/Register/Index.tsx:36,38,40**
```diff
  <input type="text" id="name"
+   autoComplete="name"
    {...field} />
  <input type="email" id="email"
+   autoComplete="email"
    {...field} />
  <input type="password" id="password"
+   autoComplete="new-password"
    {...field} />
```

**resources/js/pages/Profile/EditView.tsx:286,324,329,334,577**
```diff
  <input id="firstName"
+   autoComplete="given-name"
    {...field} />
  <input id="lastName"
+   autoComplete="family-name"
    {...field} />
  <input type="email" id="email"
+   autoComplete="email"
    {...field} />
  <input type="tel" id="phone"
+   autoComplete="tel"
    {...field} />
  <input type="password" id="currentPassword"
+   autoComplete="current-password"
    {...field} />
```

---

## 7. BUTTON TEXT VAGUE (4 files)

**resources/js/pages/Patients/MedicalHistoryFormContainer/Index.tsx:282**
```diff
- <button onClick={handleSubmit}>Submit</button>
+ <button onClick={handleSubmit} aria-label="Save medical history">
+   Save Medical History
+ </button>
```

**resources/js/pages/Profile/EditView.tsx:270**
```diff
- <button onClick={handleDelete}>Delete</button>
+ <button onClick={handleDelete} aria-label="Delete account permanently">
+   Delete Account
+ </button>
```

**resources/js/pages/Profile/EditView.tsx:379**
```diff
- <button type="submit">Save</button>
+ <button type="submit" aria-label="Save profile changes">
+   Save Changes
+ </button>
```

**resources/js/pages/Services/Create.tsx:119**
```diff
- <button onClick={handleCreate}>Create</button>
+ <button onClick={handleCreate} aria-label="Create new service">
+   Create Service
+ </button>
```

---

## 8. TOUCH TARGET SIZE (68 files - Review Required)

Many of these may be false positives if using the Button component with proper sizing.

### Quick Fix Pattern for Icon Buttons

```diff
- <button className="p-1">
+ <button className="p-2 min-w-[44px] min-h-[44px]">
    <Icon className="w-4 h-4" />
  </button>
```

### Quick Fix Pattern for Small Links

```diff
- <a className="text-sm">Link</a>
+ <a className="text-sm py-2 px-1">Link</a>
```

---

## 9. USEMEMO (32 files - Review Required)

Many are simple calculations that don't need memoization. Only wrap truly expensive operations.

### True Positives (Large Dataset Operations)

**resources/js/pages/Admin/Reports/Dashboard.tsx:104**
```diff
+ const filteredData = useMemo(() => {
    return data.filter(complexCondition).map(transform);
+ }, [data]);
```

### False Positives (Simple Operations - Skip)

```tsx
// These DON'T need useMemo:
const total = invoices.reduce((sum, inv) => sum + inv.amount, 0);
const hasItems = items.length > 0;
const displayName = user.name ?? 'Anonymous';
```

---

## Implementation Order

1. **Modal focus trap** - Fixes 27 findings with 1 change
2. **Autocomplete** - Quick find/replace across auth forms
3. **Color contrast** - Simple class replacements
4. **Status messages** - Wrap flash messages
5. **Error messages** - 3 specific files
6. **Heading order** - 1 file
7. **Button text** - 4 files
8. **Touch target** - Review individually
9. **UseMemo** - Review individually

**Estimated Time: 1.5-2 hours for confirmed fixes**
