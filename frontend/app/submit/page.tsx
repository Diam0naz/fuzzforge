"use client";

import Link from "next/link";
import { FormEvent, useState } from "react";

import { API_URL, storeToken, type SubmitResponse } from "@/lib/api";

const INVARIANT_PLACEHOLDER = `The vault balance changes only through the owner's deposit and withdraw.
The owner can always withdraw everything and close the vault.
Only the configured authority can change the fee.`;

function formatSize(bytes: number): string {
  if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024))} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export default function SubmitPage() {
  const [file, setFile] = useState<File | null>(null);
  const [invariantSpec, setInvariantSpec] = useState("");
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);

    if (!file) {
      setError("Choose a .tar or .tar.gz bundle to upload.");
      return;
    }

    setBusy(true);
    try {
      const body = new FormData();
      body.append("bundle", file);
      body.append("invariant_spec", invariantSpec);
      if (email.trim()) body.append("email", email.trim());

      const response = await fetch(`${API_URL}/jobs`, { method: "POST", body });

      if (!response.ok) {
        const payload = (await response.json().catch(() => ({}))) as { error?: string };
        throw new Error(payload.error ?? `Upload failed: ${response.status} ${response.statusText}`);
      }

      const job = (await response.json()) as SubmitResponse;
      storeToken(job.id, job.token);
      window.location.assign(`/jobs/${job.id}?token=${encodeURIComponent(job.token)}`);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
      setBusy(false);
    }
  }

  return (
    <main className="page">
      <div className="wrap">
        <div className="page-head">
          <h1>Upload a program bundle</h1>
          <p>
            For scoped engagements. The campaign starts as soon as the upload
            finishes, and you get a private link to follow it and download the
            report.
          </p>
        </div>

        <div className="two-col">
          <form className="sheet" onSubmit={onSubmit} noValidate>
            {error ? (
              <p className="form-error" role="alert">
                {error}
              </p>
            ) : null}

            <div className="field">
              <span className="label" id="bundle-label">
                Bundle
              </span>
              <label className={`dropzone${file ? " has-file" : ""}`}>
                <input
                  id="bundle"
                  name="bundle"
                  type="file"
                  aria-labelledby="bundle-label"
                  aria-describedby="bundle-hint"
                  accept=".tar,.tar.gz,.tgz,application/gzip,application/x-tar"
                  onChange={(event) => setFile(event.target.files?.[0] ?? null)}
                />
                {file ? (
                  <>
                    <strong>{file.name}</strong>
                    <span>{formatSize(file.size)}. Choose again to replace it.</span>
                  </>
                ) : (
                  <>
                    <strong>Choose a .tar or .tar.gz file</strong>
                    <span>Up to 100 MB</span>
                  </>
                )}
              </label>
              <span className="hint" id="bundle-hint">
                Anchor.toml at the root and your program under programs/.
              </span>
            </div>

            <div className="field">
              <label htmlFor="invariant">What must always be true?</label>
              <textarea
                id="invariant"
                name="invariant_spec"
                value={invariantSpec}
                onChange={(event) => setInvariantSpec(event.target.value)}
                placeholder={INVARIANT_PLACEHOLDER}
                maxLength={8000}
                aria-describedby="invariant-hint"
              />
              <span className="hint" id="invariant-hint">
                Plain sentences are fine. They appear word for word in the report.
              </span>
            </div>

            <div className="field">
              <label htmlFor="email">Email (optional)</label>
              <input
                id="email"
                name="email"
                type="email"
                autoComplete="email"
                value={email}
                onChange={(event) => setEmail(event.target.value)}
                aria-describedby="email-hint"
              />
              <span className="hint" id="email-hint">
                Only used to contact you about this campaign.
              </span>
            </div>

            <div className="actions">
              <button className="btn btn-primary" type="submit" disabled={busy}>
                {busy ? "Uploading…" : "Upload and start campaign"}
              </button>
              <Link href="/" className="btn btn-quiet">
                Cancel
              </Link>
            </div>
          </form>

          <aside className="aside" aria-label="Before you upload">
            <h2>Before you upload</h2>
            <ul>
              <li>Upload only code you&apos;re allowed to share with us.</li>
              <li>Remove keys, wallets and .env files. The bundle runs as untrusted code with no network.</li>
              <li>
                Vendor your Cargo dependencies, or include Cargo.lock. The sandbox
                can&apos;t download crates.
              </li>
              <li>
                If you have a Trident harness, put it under trident-tests/ and
                we&apos;ll run it as is.
              </li>
            </ul>
            <pre aria-label="Expected bundle layout">{`Anchor.toml
Cargo.lock
programs/
  your_program/
trident-tests/   (optional)`}</pre>
          </aside>
        </div>
      </div>
    </main>
  );
}
