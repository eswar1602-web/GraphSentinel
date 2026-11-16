import { useState } from "react";
import { api } from "../../api";
import { setParams, useRoute } from "../router";
import { useLive } from "../live";
import { Empty, Failure, Field, Figures, Loading, PageHead, Section, useData } from "../ui";
import { int, utcDateTime } from "../format";

const PAGE = 50;
const DEMO = {
  "1_clean": "Untouched log, with a checkpoint", "2_modified_details": "One record's details edited",
  "3_rechained_without_key": "Edited, then SHA-256 chain recomputed without the key",
  "4_truncated_no_checkpoint": "Newest record deleted, verified without a checkpoint",
  "5_truncated_with_checkpoint": "Newest record deleted, verified against a checkpoint",
};

function Checkpoint({ head }) {
  const [id, setId] = useState("");
  const [hash, setHash] = useState("");
  const [res, setRes] = useState(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    try {
      setRes(await api(`/api/audit/verify?checkpoint_event_id=${encodeURIComponent(id)}&checkpoint_hash=${encodeURIComponent(hash.trim())}`));
    } catch (error) { setRes({ error }); } finally { setBusy(false); }
  };
  return (
    <Section title="Check against a checkpoint" note="Store the head event and hash somewhere the log's owner cannot change. Checking against it later detects deleted or rewritten records.">
      <form className="stack" onSubmit={submit}>
        <div className="form-grid form-grid--cp">
          <Field label="Event number" htmlFor="cp-id">
            <input id="cp-id" name="checkpoint_event_id" className="control measure" inputMode="numeric" pattern="[0-9]+" required autoComplete="off"
              value={id} onChange={(e) => setId(e.target.value)} />
          </Field>
          <Field label="Hash at that event" htmlFor="cp-hash">
            <input id="cp-hash" name="checkpoint_hash" className="control measure" pattern="[0-9a-fA-F]{64}" required autoComplete="off" spellCheck="false"
              value={hash} onChange={(e) => setHash(e.target.value)} />
          </Field>
        </div>
        <div className="btn-row">
          <button type="submit" className="btn btn--quiet" disabled={busy} aria-busy={busy}>Check</button>
          {head && <button type="button" className="btn btn--quiet" onClick={() => { setId(String(head.event_id)); setHash(head.hash); }}>Use the current head</button>}
        </div>
      </form>
      {res?.error && <p className="field-error" role="alert">{res.error.message}</p>}
      {res && !res.error && (
        <p className={`verdict ${res.valid ? "verdict--ok" : "verdict--bad"}`} role="status">
          {res.valid ? "Matches: the log has not been truncated or rewritten since that checkpoint." : `Does not match: ${res.errors.map((e) => `event ${e.event_id}: ${e.error}`).join("; ")}`}
        </p>
      )}
    </Section>
  );
}

function Demo() {
  const [res, setRes] = useState(null);
  const [busy, setBusy] = useState(false);
  const run = async () => {
    setBusy(true);
    try { setRes(await api("/api/audit/demo", { method: "POST" })); } catch (error) { setRes({ error }); } finally { setBusy(false); }
  };
  return (
    <Section title="Tamper demonstration" note="Runs on a temporary log with a temporary key. The real log is never touched."
      actions={<button type="button" className="btn btn--quiet" onClick={run} disabled={busy} aria-busy={busy}>{res ? "Run again" : "Run demonstration"}</button>}>
      {busy && !res && <Loading rows={5} />}
      {res?.error && <Failure error={res.error} onRetry={run} />}
      {res && !res.error && (
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th>Case</th><th>Verdict</th><th className="num">First bad event</th><th>Reason</th></tr></thead>
            <tbody>
              {Object.entries(res).map(([k, v]) => (
                <tr key={k}>
                  <td>{DEMO[k] || k}</td>
                  <td><span className={v.valid ? "ok" : "bad"}>{v.valid ? "Valid" : "Tampering detected"}</span></td>
                  <td className="num measure">{v.first_invalid_event_id ?? "—"}</td>
                  <td className="muted">{v.errors[0]?.error || (k === "4_truncated_no_checkpoint" ? "Truncation is invisible without a checkpoint" : "—")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Section>
  );
}

export default function Audit() {
  const { params } = useRoute();
  const { versions } = useLive();
  const verify = useData("/api/audit/verify", [versions.incidents]);
  const total = verify.data?.records || 0;
  const page = Math.max(1, Number(params.page) || 1);
  const pages = Math.max(1, Math.ceil(total / PAGE));
  const offset = Math.max(0, total - page * PAGE);
  const limit = Math.min(PAGE, total - (page - 1) * PAGE);
  const recs = useData(verify.data ? `/api/audit/records?limit=${Math.max(1, limit)}&offset=${offset}` : null, [total, page]);
  const [open, setOpen] = useState(null);
  const v = verify.data;
  return (
    <>
      <PageHead title="Audit log"
        actions={<button type="button" className="btn btn--primary" onClick={() => { verify.reload(); }} disabled={verify.loading} aria-busy={verify.loading}>Verify the chain</button>}>
        Every security event is a record in a SHA-256 hash chain, authenticated with HMAC-SHA256. Verification recomputes every hash and every HMAC.
      </PageHead>
      {verify.error && !v ? <Failure error={verify.error} onRetry={verify.reload} /> : verify.loading && !v ? <Loading rows={2} /> : (
        <>
          <p className={`verdict ${v.valid ? "verdict--ok" : "verdict--bad"}`} role="status">
            {v.valid ? `Valid: all ${int(v.records)} records verify, chain and HMAC.` : `Invalid from event ${v.first_invalid_event_id}: ${v.errors.slice(0, 3).map((e) => e.error).join("; ")}`}
          </p>
          <Figures items={[["Records", int(v.records)], ["Head hash", `${v.head_hash.slice(0, 16)}…`]]} />
        </>
      )}
      <div className="grid-2">
        <Checkpoint head={recs.data?.head} />
        <Demo />
      </div>
      <Section title="Records" note="Newest first. Select a record to see its details and hashes."
        actions={total > PAGE ? (
          <div className="pager">
            <button type="button" className="btn btn--quiet btn--sm" disabled={page <= 1} onClick={() => setParams({ page: page - 1 })}>Newer</button>
            <span className="measure">{page} / {pages}</span>
            <button type="button" className="btn btn--quiet btn--sm" disabled={page >= pages} onClick={() => setParams({ page: page + 1 })}>Older</button>
          </div>
        ) : null}>
        {recs.error && !recs.data ? <Failure error={recs.error} onRetry={recs.reload} /> : (recs.loading && !recs.data) || !verify.data ? <Loading rows={8} />
          : !recs.data.records.length ? <Empty>The log is empty.</Empty> : (
            <div className="table-wrap">
              <table className="table table--select">
                <thead><tr><th className="num">Event</th><th>Time</th><th>Type</th><th>Hash</th></tr></thead>
                <tbody>
                  {recs.data.records.slice().reverse().map((r) => (
                    <FragmentRow key={r.event_id} r={r} open={open === r.event_id} onToggle={() => setOpen(open === r.event_id ? null : r.event_id)} />
                  ))}
                </tbody>
              </table>
            </div>
          )}
      </Section>
    </>
  );
}

function FragmentRow({ r, open, onToggle }) {
  return (
    <>
      <tr aria-selected={open}>
        <td className="num measure"><button type="button" className="row-link" aria-expanded={open} onClick={onToggle}>{r.event_id}</button></td>
        <td className="measure">{utcDateTime(r.timestamp)}</td>
        <td>{r.event_type.replace(/_/g, " ")}</td>
        <td className="measure muted">{r.hash.slice(0, 16)}…</td>
      </tr>
      {open && (
        <tr className="expanded">
          <td colSpan={4}>
            <pre className="code">{JSON.stringify(r.details, null, 2)}</pre>
            <dl className="kv"><div><dt>Previous hash</dt><dd className="measure wrap">{r.prev_hash}</dd></div>
              <div><dt>Hash</dt><dd className="measure wrap">{r.hash}</dd></div><div><dt>HMAC</dt><dd className="measure wrap">{r.hmac}</dd></div></dl>
          </td>
        </tr>
      )}
    </>
  );
}
