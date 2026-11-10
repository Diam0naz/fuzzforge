import Link from "next/link";

import { CONTACT_EMAIL } from "@/lib/api";

const FINDINGS = [
  {
    id: "F1",
    mint: "1% transfer fee",
    breaks: "The vault can never be closed after a deposit: withheld fees block the close.",
    replay: "2 actions",
  },
  {
    id: "F2",
    mint: "Permanent delegate",
    breaks: "A third party drains the vault without the owner's signature.",
    replay: "2 actions",
  },
  {
    id: "F3",
    mint: "Freeze authority",
    breaks: "A third party locks the owner's deposits indefinitely.",
    replay: "3 actions",
  },
  {
    id: "F4",
    mint: "Transfer hook",
    breaks: "The vault accepts the mint at setup, then every deposit fails.",
    replay: "Setup check",
  },
  {
    id: "F5",
    mint: "Non-transferable",
    breaks: "The vault accepts the mint at setup, then every deposit fails.",
    replay: "Setup check",
  },
];

export default function HomePage() {
  return (
    <main>
      <section className="hero">
        <div className="wrap hero-grid">
          <div className="hero-copy">
            <h1>Anchor ships a fuzzer. We bring the attacks it doesn&apos;t know to try.</h1>
            <p className="lede">
              Fuzzforge is pre-audit fuzzing for Solana programs. We test your
              program against hostile Token-2022 mints and the invariants your
              protocol depends on, and hand you every failure as a case you can
              replay.
            </p>
            <div className="actions">
              <a className="btn btn-primary" href={`mailto:${CONTACT_EMAIL}`}>
                Request an engagement
              </a>
              <a className="btn btn-quiet" href="#findings">
                Read the sample findings
              </a>
            </div>
          </div>

          <article className="specimen" aria-label="Example finding">
            <header className="specimen-head">
              <h2>Finding F1</h2>
              <span>Sample report</span>
            </header>
            <dl className="specimen-facts">
              <dt>Program</dt>
              <dd>token_vault, Anchor 0.32.1</dd>
              <dt>Mint</dt>
              <dd>Token-2022 with a 1% transfer fee</dd>
              <dt>Property</dt>
              <dd>The owner can always withdraw everything and close</dd>
            </dl>
            <ol className="replay" aria-label="Minimized replay">
              <li>
                <span>deposit 3,672,454</span>
                <span className="ok">ok</span>
              </li>
              <li>
                <span>withdraw 3,635,729</span>
                <span className="ok">ok</span>
              </li>
              <li>
                <span>close</span>
                <span className="fail">fails</span>
                <span className="detail">AccountHasWithheldTransferFees</span>
              </li>
            </ol>
            <div className="specimen-result">
              <strong>36,725 base units of withheld fees keep the vault from ever closing.</strong>
              <p>Fix: harvest withheld fees before closing, or reject fee-bearing mints.</p>
            </div>
          </article>
        </div>
      </section>

      <section className="section" id="method">
        <div className="wrap">
          <div className="section-head">
            <h2>What a fuzzer can&apos;t decide for you</h2>
            <p>
              Coverage-guided engines like Crucible and Trident explore
              instruction sequences quickly. They can&apos;t know which mints
              your program will meet, what an attacker would do between your
              instructions, or what must always stay true. That knowledge is the
              engagement.
            </p>
          </div>
          <dl className="method-list">
            <div className="method-row">
              <dt>Hostile mint matrix</dt>
              <dd>
                Every token flow runs against ten mint types created through the
                real Token-2022 program: transfer fees, including capped and
                100% fees, permanent delegates, transfer hooks, freeze
                authorities, non-transferable and interest-bearing mints.
                Crucible&apos;s own account probes skip Token-2022 extensions.
                Ours exist for exactly that gap.
              </dd>
            </div>
            <div className="method-row">
              <dt>Invariants written for your protocol</dt>
              <dd>
                Custody, so balances move only through authorized flows. Exit
                liveness, so users can always get their funds out. LP share value
                for AMMs, and solvency against booked fees. Writing them down is
                a design review in itself, and the specification is yours to keep.
              </dd>
            </div>
            <div className="method-row">
              <dt>Proof the harness is watching</dt>
              <dd>
                Each campaign also runs with a canary that leaks a single token
                unit outside your program. If the invariants don&apos;t catch it,
                a clean result doesn&apos;t count.
              </dd>
            </div>
          </dl>
        </div>
      </section>

      <section className="section" id="findings">
        <div className="wrap">
          <div className="section-head">
            <h2>Sample findings: an Anchor token vault</h2>
            <p>
              A vault that accepts any Token-2022 mint, tested against seven
              mint types. Five broke a property. The two control mints, classic
              SPL Token and Token-2022 without extensions, broke nothing.
            </p>
          </div>
          <div className="table-scroll">
            <table className="findings">
              <thead>
                <tr>
                  <th scope="col">ID</th>
                  <th scope="col">Mint</th>
                  <th scope="col">What breaks</th>
                  <th scope="col">Reproduces from</th>
                </tr>
              </thead>
              <tbody>
                {FINDINGS.map((f) => (
                  <tr key={f.id}>
                    <td>{f.id}</td>
                    <td className="mint">{f.mint}</td>
                    <td>{f.breaks}</td>
                    <td className="replay-col">{f.replay}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <p className="table-note">
            Each finding comes with a fix. Here, one extension allowlist in the
            vault&apos;s initialize instruction removes four of the five.
          </p>
        </div>
      </section>

      <section className="section" id="engagements">
        <div className="wrap">
          <div className="section-head">
            <h2>How an engagement runs</h2>
          </div>
          <ol className="steps">
            <li>
              <h3>Scope</h3>
              <p>
                Send a repository and commit. We agree on the instructions in
                scope, the invariants worth asserting, and a fixed quote.
              </p>
            </li>
            <li>
              <h3>Build and run</h3>
              <p>
                We write the harness for your program, run it against the mint
                matrix and Crucible&apos;s account probes, and shrink every
                failure to its shortest replay.
              </p>
            </li>
            <li>
              <h3>Report and hand over</h3>
              <p>
                You get the report, the replayable cases and the harness itself,
                ready to run in your CI on every release.
              </p>
            </li>
          </ol>
          <div className="terms">
            <div className="term">
              <h3>Pilot</h3>
              <p>
                You pay only if we find something. For a first program, so you
                can judge the work before committing budget.
              </p>
            </div>
            <div className="term">
              <h3>Engagement</h3>
              <p>
                A fixed quote after scoping, based on the program&apos;s size and
                the number of invariants.
              </p>
            </div>
            <div className="term">
              <h3>Release re-runs</h3>
              <p>
                Each upgrade is fuzzed against the previous version&apos;s
                harness before it ships. Billed per release.
              </p>
            </div>
          </div>
        </div>
      </section>

      <section className="section">
        <div className="wrap scope">
          <h2>What a report says, and what it doesn&apos;t</h2>
          <div className="scope-body">
            <p>
              A report lists what failed under stated conditions: the program
              build, the engine version, and the mints and invariants tested. A
              property that held was not proven to hold.
            </p>
            <p>
              This is pre-audit work, not an audit, and we never describe a
              program as secure. Code you send is used only for the engagement
              and is never shared without your written permission.
            </p>
          </div>
        </div>
      </section>

      <section className="section closing">
        <div className="wrap closing-grid">
          <div>
            <h2>Heading to audit? Find the cheap bugs first.</h2>
            <p>
              Tell us what the program does and when the audit starts. You&apos;ll
              get a scope and a quote within two working days.
            </p>
          </div>
          <div className="closing-aside">
            <a className="btn btn-primary" href={`mailto:${CONTACT_EMAIL}`}>
              Request an engagement
            </a>
            <p>
              Or write to <a href={`mailto:${CONTACT_EMAIL}`}>{CONTACT_EMAIL}</a>.
              Already scoped? <Link href="/submit">Upload your bundle</Link>.
            </p>
          </div>
        </div>
      </section>
    </main>
  );
}
