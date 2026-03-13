export function patientPortalSection(pathname: string): string {
  return pathname.startsWith("/patients") ? "patients" : "dashboard";
}
