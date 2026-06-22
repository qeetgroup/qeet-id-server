import { ConsentForm, type ConsentParams } from "./consent-form";

export default async function ConsentPage({
  searchParams,
}: {
  searchParams: Promise<Record<string, string | undefined>>;
}) {
  const sp = await searchParams;
  const params: ConsentParams = {
    client_id: sp.client_id ?? "",
    redirect_uri: sp.redirect_uri ?? "",
    scope: sp.scope ?? "",
    state: sp.state ?? "",
    nonce: sp.nonce ?? "",
    code_challenge: sp.code_challenge ?? "",
    code_challenge_method: sp.code_challenge_method ?? "",
  };
  return <ConsentForm params={params} />;
}
