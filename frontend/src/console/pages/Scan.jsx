import { useRef, useState } from "react";
import { api } from "../../api";
import { setParams, useRoute } from "../router";
import { Bars, Empty, Failure, Field, Figures, KV, Loading, PageHead, Section, useData } from "../ui";
import { int, num, utcDateTime } from "../format";

const MAX_MB = 25;

function Result({ r }) {
  const fam = Object.entries(r.predicted_family_counts).sort((a, b) => b[1] - a[1]);
  const gt = r.ground_truth_evaluation;
  return (
    <>
      <Figures items={[["Flows", int(r.n_flows)], ["Scored", int(r.n_scored)], ["Predicted attacks", int(r.n_alerts)],
        ["Invalid records", int(r.n_invalid_negative_duration)]]} />
      <div className="grid-2">
        <Section title="Predicted classes" note={`${r.model}, ${r.features_used} features, destination port ${r.destination_port_used ? "used" : "not used"}.`}>
          <Bars rows={fam} total={r.n_flows} />
        </Section>
        <Section title="Record" note="Stored in the scan history and the audit log.">
          <KV items={[["File", r.filename, true], ["SHA-256", r.file_sha256, true], ["Scan", `#${r.detection_id}`, true],
            ["Audit record", `#${r.audit_event_id}`, true], ["Value corrections", int(r.value_corrections), true],
            gt ? ["Macro-F1 against the file's labels", `${num(gt.overall.macro_f1, 3)} on ${int(gt.n)} flows`, true] : null]} />
          {gt && <p className="note">The file had a Label column. It was used only to score the result, never as an input.</p>}
        </Section>
      </div>
      <Section title="First flows" note={`The first ${Math.min(20, r.preview.length)} of ${int(r.n_flows)} rows; flagged rows are marked.`}>
        <div className="table-wrap">
          <table className="table">
            <thead><tr><th className="num">Row</th><th>Source</th><th>Destination</th><th>Timestamp in file</th><th>Predicted</th><th className="num">Confidence</th></tr></thead>
            <tbody>
              {r.preview.slice(0, 20).map((p) => (
                <tr key={p.row} className={p.predicted !== "Benign" ? "is-flagged" : undefined}>
                  <td className="num measure">{p.row + 1}</td><td className="measure">{p["Source IP"] ?? "—"}</td>
                  <td className="measure">{p["Destination IP"] ?? "—"}</td><td className="measure">{p.Timestamp ?? "—"}</td>
                  <td>{p.predicted}</td><td className="num measure">{p.confidence === null ? "—" : num(p.confidence, 3)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Section>
    </>
  );
}

export default function Scan() {
  const { params } = useRoute();
  const input = useRef(null);
  const [file, setFile] = useState(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  const history = useData("/api/detections?limit=50", [result?.detection_id]);
  const tooBig = file && file.size > MAX_MB * 1024 * 1024;

  const submit = async (e) => {
    e.preventDefault();
    if (!file || tooBig) return;
    setBusy(true);
    setError(null);
    try {
      const fd = new FormData();
      fd.append("file", file);
      setResult(await api("/api/detect", { method: "POST", body: fd }));
    } catch (err) {
      setError(err);
      input.current?.focus();
    } finally { setBusy(false); }
  };

  const picked = params.scan && history.data ? history.data.find((h) => String(h.id) === params.scan) : null;

  return (
    <>
      <PageHead title="File scan">
        Classify the flows in a CICIDS2017-format CSV export with the XGBoost model. This is separate from the simulated network.
      </PageHead>
      <Section title="Upload">
        <form className="scan-form" onSubmit={submit}>
          <Field label="Flow export (.csv, up to 25 MB)" htmlFor="scan-file"
            hint={tooBig ? `This file is ${(file.size / 1048576).toFixed(1)} MB; the limit is ${MAX_MB} MB.` : file ? `${file.name}, ${(file.size / 1024).toFixed(0)} kB` : "Make one from the dataset: python -m src.api.make_sample"}>
            <input ref={input} id="scan-file" name="file" type="file" accept=".csv,text/csv" className="control control--file"
              aria-invalid={tooBig || !!error} onChange={(e) => { setFile(e.target.files?.[0] || null); setError(null); }} />
          </Field>
          <div className="btn-row">
            <button type="submit" className="btn btn--primary" disabled={!file || tooBig || busy} aria-busy={busy}>{busy ? "Scanning" : "Scan file"}</button>
          </div>
        </form>
        {error && <p className="field-error" role="alert">{error.message}</p>}
      </Section>
      {busy && <Loading rows={4} label="Scanning" />}
      {result && <Result r={result} />}
      <Section title="Scan history">
        {history.error && !history.data ? <Failure error={history.error} onRetry={history.reload} />
          : history.loading && !history.data ? <Loading rows={4} />
            : !history.data.length ? <Empty>No files scanned yet.</Empty> : (
              <div className={picked ? "split" : undefined}>
                <div className="table-wrap">
                  <table className="table table--select">
                    <thead><tr><th>Scanned</th><th>File</th><th className="num">Flows</th><th className="num">Predicted attacks</th></tr></thead>
                    <tbody>
                      {history.data.map((h) => (
                        <tr key={h.id} aria-selected={String(h.id) === params.scan}>
                          <td className="measure"><a className="row-link" href={`#/scan?scan=${h.id}`}>{utcDateTime(h.created_at)}</a></td>
                          <td className="measure">{h.filename}</td><td className="num measure">{int(h.n_flows)}</td><td className="num measure">{int(h.n_alerts)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                {picked && (
                  <Section title={picked.filename} className="detail" note={`Scan #${picked.id}`}
                    actions={<button type="button" className="btn btn--quiet btn--sm" onClick={() => setParams({ scan: null })}>Close</button>}>
                    <KV items={[["Scanned", utcDateTime(picked.created_at), true], ["SHA-256", picked.file_sha256, true], ["Model", picked.model, true],
                      ["Scored", `${int(picked.n_scored)} of ${int(picked.n_flows)}`, true],
                      picked.summary.ground_truth_macro_f1 !== undefined ? ["Macro-F1 against labels", num(picked.summary.ground_truth_macro_f1, 3), true] : null]} />
                    <h3 className="sub">Predicted classes</h3>
                    <Bars rows={Object.entries(picked.summary.predicted_family_counts || {}).sort((a, b) => b[1] - a[1])} total={picked.n_flows} />
                  </Section>
                )}
              </div>
            )}
      </Section>
    </>
  );
}
