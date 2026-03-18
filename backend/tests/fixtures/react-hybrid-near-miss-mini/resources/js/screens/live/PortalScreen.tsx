import { Head } from "@inertiajs/react";
import { useTheme } from "../../composables/useTheme";
import { buildPortalLabel } from "./helpers/portalHelper";
import { formatPortalTimer } from "./lib/portalTimer";
import { createPortalService } from "./services/livePortalService";

export default function PortalScreen() {
  const theme = useTheme();
  const service = createPortalService();

  return (
    <section data-theme={theme.mode}>
      <Head title="Portal" />
      <h1>{buildPortalLabel("live")}</h1>
      <p>{formatPortalTimer(30)}</p>
      <small>{String(service.sync())}</small>
    </section>
  );
}
