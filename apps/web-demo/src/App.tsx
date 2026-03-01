import { useMemo, useState } from "react";

const appGatewayUrl = (import.meta.env.VITE_APP_GATEWAY_BASE_URL as string | undefined)?.trim();

export default function App() {
  const [action, setAction] = useState("identity.verify");
  const [status, setStatus] = useState<string>("");

  const gateway = useMemo(() => {
    if (!appGatewayUrl) return null;
    return appGatewayUrl.replace(/\/$/, "");
  }, []);

  const checkRequirements = async () => {
    if (!gateway) {
      setStatus("VITE_APP_GATEWAY_BASE_URL is not configured.");
      return;
    }
    try {
      const res = await fetch(`${gateway}/v1/requirements?action=${encodeURIComponent(action)}`);
      if (!res.ok) {
        setStatus(`Requirements failed (${res.status}).`);
        return;
      }
      setStatus("Requirements fetched. SSI-only web demo is configured.");
    } catch (error) {
      setStatus(error instanceof Error ? error.message : String(error));
    }
  };

  return (
    <main style={{ fontFamily: "system-ui, sans-serif", margin: "2rem auto", maxWidth: 760 }}>
      <h1>CUNCTA Web Demo (SSI-only)</h1>
      <p>Web wallet scope is presentation and verification only.</p>
      <p>Create your identity using the CUNCTA mobile wallet.</p>

      <section style={{ marginTop: "1.5rem" }}>
        <label htmlFor="action-input">Verification action</label>
        <div style={{ display: "flex", gap: "0.5rem", marginTop: "0.5rem" }}>
          <input
            id="action-input"
            value={action}
            onChange={(event) => setAction(event.target.value)}
            style={{ flex: 1, padding: "0.5rem" }}
          />
          <button type="button" onClick={checkRequirements}>
            Check requirements
          </button>
        </div>
      </section>

      {status ? (
        <pre
          style={{
            marginTop: "1rem",
            padding: "0.75rem",
            background: "#111",
            color: "#eee",
            borderRadius: 8,
            whiteSpace: "pre-wrap"
          }}
        >
          {status}
        </pre>
      ) : null}
    </main>
  );
}
