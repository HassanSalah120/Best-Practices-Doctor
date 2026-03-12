import { Severity, type Severity as SeverityT } from "@/types/api";

export function getSeverityBadgeVariant(severity: SeverityT) {
  switch (severity) {
    case Severity.CRITICAL:
      return "critical";
    case Severity.HIGH:
      return "high";
    case Severity.MEDIUM:
      return "medium";
    case Severity.LOW:
      return "low";
    case Severity.INFO:
      return "info";
    default:
      return "default";
  }
}
