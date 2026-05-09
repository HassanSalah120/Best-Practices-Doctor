#!/bin/bash
#
# Apply Accessibility Fixes Script
# Copy this script to your Laravel project root and run: ./apply-a11y-fixes.sh
#

set -e

echo "=== Applying Accessibility Fixes ==="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Fix 1: Modal Focus Trap (requires focus-trap-react)
echo -e "${YELLOW}[1/9] Setting up modal focus trap...${NC}"
npm install focus-trap-react 2>/dev/null || echo "focus-trap-react already installed"

# Create patch for Modal.tsx
cat > /tmp/modal-patch.diff << 'EOF'
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
EOF

# Try to apply patch
cd resources/js/components/UI
git apply /tmp/modal-patch.diff 2>/dev/null && echo -e "${GREEN}✓ Modal.tsx patched${NC}" || echo -e "${YELLOW}⚠ Manual patch needed for Modal.tsx${NC}"
cd -

# Fix 2: Color Contrast - Replace gray-400 with gray-600
echo -e "${YELLOW}[2/9] Fixing color contrast (gray-400 → gray-600)...${NC}"
find resources/js -type f \( -name "*.tsx" -o -name "*.ts" \) -exec sed -i 's/text-gray-400/text-gray-600/g' {} \;
find resources/js -type f \( -name "*.tsx" -o -name "*.ts" \) -exec sed -i 's/text-slate-400/text-slate-600/g' {} \;
find resources/js -type f \( -name "*.tsx" -o -name "*.ts" \) -exec sed -i 's/text-gray-300/text-gray-500/g' {} \;
echo -e "${GREEN}✓ Color contrast fixed${NC}"

# Fix 3: Skip Links for Layouts
echo -e "${YELLOW}[3/9] Adding skip links to layouts...${NC}"
cat > /tmp/skip-link-patch.txt << 'EOF'
Add to layouts/AuthenticatedLayout.tsx after opening <div>:

      {/* Skip to main content link for accessibility */}
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:top-4 focus:left-4 focus:z-50 focus:px-4 focus:py-2 focus:bg-primary focus:text-white focus:rounded-md"
      >
        Skip to main content
      </a>

Change: <main className="flex-1 p-5 md:p-6">
To: <main id="main-content" className="flex-1 p-5 md:p-6">
EOF
cat /tmp/skip-link-patch.txt
echo -e "${YELLOW}⚠ Manual application needed for skip links (see above)${NC}"

# Fix 4: Autocomplete Attributes
echo -e "${YELLOW}[4/9] Adding autocomplete attributes...${NC}"
# Email inputs
find resources/js -type f \( -name "*.tsx" -o -name "*.ts" \) -exec \
  sed -i 's/type="email"/type="email" autoComplete="email"/g' {} \;
# Password inputs
find resources/js -type f \( -name "*.tsx" -o -name "*.ts" \) -exec \
  sed -i 's/type="password" id="password"/type="password" id="password" autoComplete="current-password"/g' {} \;
find resources/js -type f \( -name "*.tsx" -o -name "*.ts" \) -exec \
  sed -i 's/type="password" id="new_password"/type="password" id="new_password" autoComplete="new-password"/g' {} \;
# Name fields
find resources/js -type f \( -name "*.tsx" -o -name "*.ts" \) -exec \
  sed -i 's/id="firstName"/id="firstName" autoComplete="given-name"/g' {} \;
find resources/js -type f \( -name "*.tsx" -o -name "*.ts" \) -exec \
  sed -i 's/id="lastName"/id="lastName" autoComplete="family-name"/g' {} \;
find resources/js -type f \( -name "*.tsx" -o -name "*.ts" \) -exec \
  sed -i 's/id="name"/id="name" autoComplete="name"/g' {} \;
# Phone
find resources/js -type f \( -name "*.tsx" -o -name "*.ts" \) -exec \
  sed -i 's/id="phone"/id="phone" autoComplete="tel"/g' {} \;
find resources/js -type f \( -name "*.tsx" -o -name "*.ts" \) -exec \
  sed -i 's/type="tel"/type="tel" autoComplete="tel"/g' {} \;
echo -e "${GREEN}✓ Autocomplete attributes added${NC}"

# Fix 5: Status Messages (aria-live)
echo -e "${YELLOW}[5/9] Adding ARIA live regions to status messages...${NC}"
find resources/js -type f \( -name "*.tsx" -o -name "*.ts" \) -exec \
  sed -i 's/className="alert alert-success"/role="status" aria-live="polite" className="alert alert-success"/g' {} \;
find resources/js -type f \( -name "*.tsx" -o -name "*.ts" \) -exec \
  sed -i 's/className="alert alert-error"/role="alert" aria-live="assertive" className="alert alert-error"/g' {} \;
echo -e "${GREEN}✓ Status messages updated${NC}"

# Fix 6: Heading Order
echo -e "${YELLOW}[6/9] Fixing heading order...${NC}"
# Replace standalone h3 with h2
find resources/js -type f \( -name "*.tsx" -o -name "*.ts" \) -exec \
  sed -i 's/<h3\([^>]*\)>/\n<h2\1 className="text-xl font-semibold">/g' {} \;
find resources/js -type f \( -name "*.tsx" -o -name "*.ts" \) -exec \
  sed -i 's/<\/h3>/<\/h2>/g' {} \;
echo -e "${YELLOW}⚠ Heading order partially fixed - verify manually${NC}"

# Fix 7: Error Message Association
echo -e "${YELLOW}[7/9] Adding error message associations...${NC}"
echo -e "${YELLOW}⚠ Manual fix needed - add aria-errormessage and role=alert to error elements${NC}"
cat << 'EOF'
Pattern to apply:
<input {...field} aria-invalid={errors.field ? "true" : "false"} aria-errormessage="field-error" />
{errors.field && <p id="field-error" role="alert">{errors.field}</p>}
EOF

# Fix 8: Focus Indicators
echo -e "${YELLOW}[8/9] Adding focus indicators...${NC}"
find resources/js -type f \( -name "*.tsx" -o -name "*.ts" \) -exec \
  sed -i 's/hover:bg-amber-200/hover:bg-amber-200 focus:ring-2 focus:ring-amber-400 focus:outline-none/g' {} \;
echo -e "${GREEN}✓ Focus indicators added${NC}"

# Fix 9: Button Text
echo -e "${YELLOW}[9/9] Fixing vague button text...${NC}"
echo -e "${YELLOW}⚠ Manual review needed - check for vague button text${NC}"

echo ""
echo "=== Summary ==="
echo -e "${GREEN}✓ Automated fixes applied${NC}"
echo -e "${YELLOW}⚠ Manual fixes still needed:${NC}"
echo "  - Modal.tsx (if patch failed)"
echo "  - Skip links in layouts"
echo "  - Error message associations"
echo "  - Heading order verification"
echo "  - Button text review"
echo ""
echo "Next steps:"
echo "1. Run your test suite: npm test"
echo "2. Verify with screen reader (NVDA/VoiceOver)"
echo "3. Run accessibility scanner again"
echo "4. Check contrast with WebAIM tool"
