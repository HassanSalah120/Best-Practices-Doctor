import { Head } from "@inertiajs/react";

type AppSeoProps = {
  title: string;
};

export function AppSeo({ title }: AppSeoProps) {
  return <Head title={title} />;
}
