import { useTranslation } from "react-i18next";

export function useEmailBooking() {
  const { t } = useTranslation();

  return {
    label: t("booking.email.label"),
  };
}
