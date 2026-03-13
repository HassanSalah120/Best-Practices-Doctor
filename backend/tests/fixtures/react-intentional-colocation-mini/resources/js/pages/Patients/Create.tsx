import { AppSeo } from "../../components/seo/AppSeo";
import { useEmailBooking } from "../../hooks/useEmailBooking";
import { t } from "../../i18n";
import { buildPatientDefaults } from "./Create.utils";

export default function CreatePatientPage() {
  const booking = useEmailBooking();
  const defaults = buildPatientDefaults();

  return (
    <>
      <AppSeo title={t("patients.create.title")} />
      <section data-status={defaults.status}>{booking.label}</section>
    </>
  );
}
