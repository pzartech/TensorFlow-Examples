/**
 * Didit request side (KYC) — create a verification session.
 *
 * This is the only piece deliberately left "off" until you add credentials:
 * without DIDIT_API_KEY it throws a clear error, so the rest of the system is
 * fully ready and KYC is a one-variable switch.
 *
 * NOTE: confirm the endpoint path, request body, and response field names
 * against your Didit console / docs (shapes vary by workflow).
 */
export interface SessionRequest {
  /** Pseudonymous ICI user id — travels back on the webhook as vendor_data. */
  vendorData: string;
  callbackUrl?: string;
  workflowId?: string;
}

export interface SessionResponse {
  sessionId: string;
  url: string;
}

export async function createVerificationSession(req: SessionRequest): Promise<SessionResponse> {
  const apiKey = process.env.DIDIT_API_KEY;
  if (!apiKey) {
    throw new Error('KYC not configured: set DIDIT_API_KEY to enable Didit sessions');
  }
  const base = process.env.DIDIT_API_BASE ?? 'https://verification.didit.me';

  const res = await fetch(`${base}/v2/session/`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey },
    body: JSON.stringify({
      workflow_id: req.workflowId ?? process.env.DIDIT_WORKFLOW_ID,
      vendor_data: req.vendorData,
      callback: req.callbackUrl ?? process.env.DIDIT_CALLBACK_URL,
    }),
  });
  if (!res.ok) {
    throw new Error(`Didit session create failed: ${res.status} ${await res.text()}`);
  }
  const body = (await res.json()) as Record<string, string>;
  return {
    sessionId: body.session_id ?? body.id,
    url: body.url ?? body.verification_url ?? body.session_url,
  };
}
