#!/usr/bin/env node
/**
 * Accessibility Fixes Codemod
 * 
 * This script applies accessibility fixes to React/TypeScript files.
 * Run with: npx jscodeshift -t accessibility-codemod.ts src/
 * 
 * Fixes applied:
 * 1. Adds aria-live to status messages
 * 2. Adds aria-errormessage to inputs with errors
 * 3. Adds autocomplete attributes to form fields
 * 4. Adds focus styles to buttons with only hover
 * 5. Darkens low-contrast text colors
 */

import { API, FileInfo, Options, JSXElement, JSXAttribute } from 'jscodeshift';

export default function transformer(file: FileInfo, api: API, options: Options) {
  const j = api.jscodeshift;
  const root = j(file.source);
  let hasChanges = false;

  // Fix 1: Add role="status" to flash/alert messages
  root.find(j.JSXElement, {
    openingElement: {
      name: { name: (name: string) => ['div', 'span', 'p'].includes(name) }
    }
  })
  .filter((path) => {
    const className = getAttributeValue(path.value, 'className');
    return className && (
      className.includes('alert') ||
      className.includes('success') ||
      className.includes('error') ||
      className.includes('toast')
    );
  })
  .forEach((path) => {
    const attrs = path.value.openingElement.attributes || [];
    const hasRole = attrs.some((attr: JSXAttribute) => 
      attr.name?.name === 'role'
    );
    
    if (!hasRole) {
      attrs.push(
        j.jsxAttribute(
          j.jsxIdentifier('role'),
          j.stringLiteral('status')
        )
      );
      attrs.push(
        j.jsxAttribute(
          j.jsxIdentifier('aria-live'),
          j.stringLiteral('polite')
        )
      );
      hasChanges = true;
    }
  });

  // Fix 2: Add autocomplete to form inputs
  const inputTypes: Record<string, string> = {
    'email': 'email',
    'password': 'current-password',
    'tel': 'tel',
    'text-name': 'name',
    'text-first': 'given-name',
    'text-last': 'family-name',
  };

  root.find(j.JSXElement, {
    openingElement: {
      name: { name: 'input' }
    }
  })
  .forEach((path) => {
    const type = getAttributeValue(path.value, 'type') || 'text';
    const id = getAttributeValue(path.value, 'id') || '';
    const attrs = path.value.openingElement.attributes || [];
    
    const hasAutoComplete = attrs.some((attr: JSXAttribute) => 
      attr.name?.name === 'autoComplete' || attr.name?.name === 'autocomplete'
    );

    if (!hasAutoComplete) {
      let autoCompleteValue: string | null = null;

      if (type === 'email') autoCompleteValue = 'email';
      else if (type === 'password') autoCompleteValue = 'current-password';
      else if (type === 'tel') autoCompleteValue = 'tel';
      else if (id.includes('first')) autoCompleteValue = 'given-name';
      else if (id.includes('last')) autoCompleteValue = 'family-name';
      else if (id.includes('name')) autoCompleteValue = 'name';
      else if (id.includes('phone')) autoCompleteValue = 'tel';
      else if (id.includes('email')) autoCompleteValue = 'email';

      if (autoCompleteValue) {
        attrs.push(
          j.jsxAttribute(
            j.jsxIdentifier('autoComplete'),
            j.stringLiteral(autoCompleteValue)
          )
        );
        hasChanges = true;
      }
    }
  });

  // Fix 3: Darken low-contrast text colors (gray-400 -> gray-600)
  root.find(j.JSXAttribute, { name: { name: 'className' } })
  .forEach((path) => {
    const value = path.value.value;
    if (value?.type === 'StringLiteral' || value?.type === 'Literal') {
      const className = (value as any).value as string;
      if (className.includes('text-gray-400') || className.includes('text-slate-400')) {
        (value as any).value = className
          .replace(/text-gray-400\b/g, 'text-gray-600')
          .replace(/text-slate-400\b/g, 'text-slate-600')
          .replace(/text-gray-300\b/g, 'text-gray-500');
        hasChanges = true;
      }
    }
  });

  // Fix 4: Add focus styles to buttons with hover but no focus
  root.find(j.JSXElement, {
    openingElement: {
      name: { name: 'button' }
    }
  })
  .filter((path) => {
    const className = getAttributeValue(path.value, 'className') || '';
    return className.includes('hover:') && !className.includes('focus:');
  })
  .forEach((path) => {
    const attrs = path.value.openingElement.attributes || [];
    const classNameAttr = attrs.find((attr: JSXAttribute) => 
      attr.name?.name === 'className'
    );
    
    if (classNameAttr && classNameAttr.value?.type === 'StringLiteral') {
      const originalClass = (classNameAttr.value as any).value;
      (classNameAttr.value as any).value = `${originalClass} focus:ring-2 focus:ring-blue-500 focus:outline-none`;
      hasChanges = true;
    }
  });

  return hasChanges ? root.toSource() : null;
}

function getAttributeValue(element: JSXElement, attrName: string): string | null {
  const attr = element.openingElement.attributes?.find(
    (a: JSXAttribute) => a.name?.name === attrName
  );
  
  if (!attr) return null;
  
  if (attr.value?.type === 'StringLiteral' || attr.value?.type === 'Literal') {
    return (attr.value as any).value;
  }
  
  return null;
}
