# Security & Accessibility Fixes

## 1. insecure-random-for-security (CRITICAL)

### File: app/Services/TwoFactorEmailService.php

```diff
--- a/app/Services/TwoFactorEmailService.php
+++ b/app/Services/TwoFactorEmailService.php
@@ -42,7 +42,7 @@ class TwoFactorEmailService
         // Invalidate any existing codes first
         $this->invalidateExistingCodes($user);
 
-        $code = (string) rand(100000, 999999);
+        $code = (string) random_int(100000, 999999);
         $expiresAt = now()->addMinutes($this->codeExpiryMinutes);
 
         TwoFactorEmailCode::create([
@@ -75,7 +75,7 @@ class TwoFactorEmailService
         // Invalidate any existing backup codes first
         $this->invalidateExistingCodes($user, true);
 
-        $code = (string) rand(100000, 999999);
+        $code = (string) random_int(100000, 999999);
         $expiresAt = now()->addMinutes($this->backupCodeExpiryMinutes);
 
         TwoFactorEmailCode::create([
```

**Rationale:** `rand()` is not cryptographically secure. 2FA codes require unpredictable random generation using `random_int()` which uses the operating system's CSPRNG.

**Test Coverage:** Verify 2FA code generation still works; codes should be 6 digits between 100000-999999.

---

## 2. modal-trap-focus (HIGH)

### File: resources/js/components/UI/Modal.tsx

```diff
--- a/resources/js/components/UI/Modal.tsx
+++ b/resources/js/components/UI/Modal.tsx
@@ -1,5 +1,6 @@
 import { useEffect, useRef } from "react";
 import { createPortal } from "react-dom";
+import FocusTrap from "focus-trap-react";
 
 export interface ModalProps {
   open: boolean;
@@ -78,22 +79,24 @@ export function Modal({
 
   return createPortal(
-    <div
-      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
-      onClick={handleBackdropClick}
-      role="dialog"
-      aria-modal="true"
-      aria-labelledby={titleId}
-      aria-describedby={descriptionId}
-    >
-      <div
-        ref={contentRef}
-        className={cn("relative bg-white rounded-lg shadow-lg", className)}
-        onClick={(e) => e.stopPropagation()}
+    <FocusTrap>
+      <div
+        className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4"
+        onClick={handleBackdropClick}
+        role="dialog"
+        aria-modal="true"
+        aria-labelledby={titleId}
+        aria-describedby={descriptionId}
       >
-        {children}
+        <div
+          ref={contentRef}
+          className={cn("relative bg-white rounded-lg shadow-lg", className)}
+          onClick={(e) => e.stopPropagation()}
+        >
+          {children}
+        </div>
       </div>
-    </div>,
+    </FocusTrap>,
     document.body
   );
 }
```

**Dependencies:** `npm install focus-trap-react`

**Rationale:** WCAG 2.4.3 requires focus to be trapped within modals for keyboard navigation. The FocusTrap component ensures Tab cycles within the modal and returns focus to trigger on close.

**Residual Risk:** If `focus-trap-react` adds bundle size concerns, implement manual focus trap:
```tsx
// Alternative: Manual focus trap
const onKeyDown = (e: KeyboardEvent) => {
  if (e.key === "Tab") {
    const focusable = contentRef.current?.querySelectorAll(
      'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
    );
    if (focusable.length > 0) {
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        (last as HTMLElement).focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        (first as HTMLElement).focus();
      }
    }
  }
};
```

---

## 3. skip-link-missing (HIGH)

### File: resources/js/layouts/AuthenticatedLayout.tsx

```diff
--- a/resources/js/layouts/AuthenticatedLayout.tsx
+++ b/resources/js/layouts/AuthenticatedLayout.tsx
@@ -1,6 +1,7 @@
 import { useState } from "react";
 import { Link, usePage } from "@inertiajs/react";
 import { useFlashToast } from "@/hooks/useFlashToast";
+import { Head } from "@inertiajs/react";
 
 export default function AuthenticatedLayout({
   children,
@@ -14,6 +15,13 @@ export default function AuthenticatedLayout({
 
   return (
     <div className="min-h-screen bg-gray-100">
+      {/* Skip to main content link for accessibility */}
+      <a
+        href="#main-content"
+        className="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-50 focus:px-4 focus:py-2 focus:bg-primary focus:text-white focus:rounded-md"
+      >
+        Skip to main content
+      </a>
+
       <nav className="bg-white border-b border-gray-100">
         {/* ... existing navigation ... */}
       </nav>
@@ -60,7 +68,7 @@ export default function AuthenticatedLayout({
         </aside>
       )}
 
-      <main className="flex-1 p-5 md:p-6">
+      <main id="main-content" className="flex-1 p-5 md:p-6">
         {children}
       </main>
     </div>
```

### File: resources/js/layouts/PatientPortalLayout.tsx

```diff
--- a/resources/js/layouts/PatientPortalLayout.tsx
+++ b/resources/js/layouts/PatientPortalLayout.tsx
@@ -8,6 +8,13 @@ export default function PatientPortalLayout({
 }) {
   return (
     <div className="min-h-screen bg-gray-50">
+      {/* Skip to main content link for accessibility */}
+      <a
+        href="#main-content"
+        className="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-50 focus:px-4 focus:py-2 focus:bg-primary focus:text-white focus:rounded-md"
+      >
+        Skip to main content
+      </a>
+
       <header className="bg-white shadow">
         <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
           <h1>Patient Portal</h1>
@@ -15,7 +22,7 @@ export default function PatientPortalLayout({
       </header>
 
       <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
-        <main>{children}</main>
+        <main id="main-content">{children}</main>
       </div>
     </div>
   );
```

**Rationale:** WCAG 2.4.1 Bypass Blocks requires skip links for keyboard users to bypass navigation. The `sr-only` class hides the link visually until focused.

**Test Coverage:** Verify link appears when pressing Tab on page load; clicking it moves focus to main content.

---

## 4. autocomplete-missing (29 fields)

Apply these patterns consistently across all auth and profile forms:

### Pattern for Email fields:
```diff
- <input type="email" id="email" {...field} />
+ <input type="email" id="email" autoComplete="email" {...field} />
```

### Pattern for Password fields:
```diff
- <input type="password" id="password" {...field} />
+ <input type="password" id="password" autoComplete="current-password" {...field} />
```

### Pattern for New Password:
```diff
- <input type="password" id="new_password" {...field} />
+ <input type="password" id="new_password" autoComplete="new-password" {...field} />
```

### Pattern for Name fields:
```diff
- <input type="text" id="firstName" {...field} />
+ <input type="text" id="firstName" autoComplete="given-name" {...field} />

- <input type="text" id="lastName" {...field} />
+ <input type="text" id="lastName" autoComplete="family-name" {...field} />
```

### Pattern for Phone:
```diff
- <input type="tel" id="phone" {...field} />
+ <input type="tel" id="phone" autoComplete="tel" {...field} />
```

### Pattern for Organization:
```diff
- <input type="text" id="clinic_name" {...field} />
+ <input type="text" id="clinic_name" autoComplete="organization" {...field} />
```

**Files to update (selective):**
- `resources/js/pages/Auth/Login/Index.tsx` - email (email), password (current-password)
- `resources/js/pages/Auth/Register/Index.tsx` - email (email), password (new-password)
- `resources/js/pages/Profile/EditView.tsx` - name fields, email, phone

**Rationale:** WCAG 1.3.5 Identify Input Purpose requires autocomplete attributes for user data fields to assist password managers and assistive technologies.

**Test Coverage:** Verify browsers offer to save/fill passwords after adding attributes.

---

## 5. heading-order (6 files)

### Pattern: Fix h3 → h2 when h2 is missing

```diff
  <section>
-   <h3>Section Title</h3>
+   <h2>Section Title</h2>
    <p>Content...</p>
  </section>
```

**Or add the missing h2:**
```diff
  <section>
+   <h2 className="sr-only">Dashboard Overview</h2>
    <h3>Stats</h3>
    ...
    <h3>Recent Activity</h3>
  </section>
```

**Files:**
- `resources/js/pages/Admin/Reports/Dashboard.tsx`
- `resources/js/pages/Admin/Webhooks/Index.tsx`
- `resources/js/pages/Patients/Show.tsx`
- `resources/js/pages/Portal/Clinics/ShowView.tsx`
- `resources/js/pages/Portal/CommunicationLogs/CommunicationLogsContent.tsx`
- `resources/js/pages/Welcome/SocialProof.tsx`

**Rationale:** WCAG 1.3.1 Info and Relationships requires heading levels to not skip (h1 → h2 → h3, not h1 → h3).

---

## 6. error-message-missing (3 files)

### Pattern for Input with Error:

```diff
  <div>
    <label htmlFor="email">Email</label>
    <input
      id="email"
      aria-invalid={errors.email ? "true" : "false"}
+     aria-errormessage="email-error"
      {...field}
    />
    {errors.email && (
-     <p className="text-red-500">{errors.email}</p>
+     <p id="email-error" className="text-red-500" role="alert">{errors.email}</p>
    )}
  </div>
```

**Files:**
- `resources/js/pages/Clinic/Settings/Branding/BrandingCropModal.tsx`
- `resources/js/pages/Clinic/Surveys/Create.tsx`
- `resources/js/pages/Portal/Settings/Index.tsx`

**Rationale:** WCAG 1.3.1 requires error messages to be programmatically associated with inputs via `aria-errormessage`.

---

## 7. status-message-announcement (15 files)

### Pattern for Toast/Flash Messages:

```diff
  // In layout or toast component
  {flash?.message && (
-   <div className="alert">{flash.message}</div>
+   <div role="status" aria-live="polite" className="alert">{flash.message}</div>
  )}
```

### Pattern for Success/Error States:

```diff
  {submitSuccess && (
-   <div className="text-green-600">Saved successfully!</div>
+   <div role="status" aria-live="polite" className="text-green-600">
+     Saved successfully!
+   </div>
  )}
```

**Key files:**
- `resources/js/layouts/AuthenticatedLayout.tsx` (flash toast)
- `resources/js/layouts/GuestLayout.tsx` (flash toast)
- `resources/js/pages/Appointments/Index.tsx` (status messages)

**Rationale:** WCAG 4.1.3 Status Messages requires status updates to be announced to screen readers without receiving focus.

---

## 8. color-contrast-ratio (Selective fixes)

### Text slate-400 on white backgrounds - LIKELY PASSING
Verify with WebAIM: `text-slate-400` (#94a3b8) on white (#ffffff) = 4.6:1 ratio ✓

### TRUE POSITIVES to fix:

```diff
  // Disabled state text
- <span className="text-slate-400">Inactive</span>
+ <span className="text-slate-500">Inactive</span>  // Darker gray

  // Placeholder-like text that needs to be readable
- <p className="text-slate-300">Description</p>
+ <p className="text-slate-500">Description</p>
```

**Files to verify/fix:**
- `resources/js/components/Booking/BookingCard.tsx` L76
- `resources/js/components/Booking/EmailBookingForm.tsx` L52, L60, L65, L70
- `resources/js/pages/Clinic/BookingRequests/Index.tsx` L52, L63, L101

**Rationale:** WCAG 1.4.3 Contrast requires 4.5:1 minimum for normal text.

---

## Summary Table

| Category | Files | Severity | Effort |
|----------|-------|----------|--------|
| insecure-random | 1 | CRITICAL | 2 min |
| modal-trap-focus | 1 | HIGH | 30 min (adds dep) |
| skip-link-missing | 2 | HIGH | 15 min |
| autocomplete-missing | 29 fields | MEDIUM | 30 min |
| heading-order | 6 | MEDIUM | 20 min |
| error-message-missing | 3 | MEDIUM | 15 min |
| status-message-announcement | 15 | MEDIUM | 20 min |
| color-contrast-ratio | ~10 | MEDIUM | 15 min |

**Total Estimated Time:** ~2.5 hours
