const githubUrl = "https://github.com/Atomics-hub/reproassert";

const claimSteps = [
  {
    name: "rejected",
    label: "Rejected",
    detail: "Policy, collection, setup, or evidence failed.",
    state: "available",
  },
  {
    name: "collected",
    label: "Collected",
    detail: "The exact candidate test exists and pytest can collect it.",
    state: "available",
  },
  {
    name: "repeatable_base_failure",
    label: "Repeatable base failure",
    detail: "Same issue-marked failure on every bounded base rerun.",
    state: "ceiling",
  },
  {
    name: "differential_reproduction",
    label: "Differential reproduction",
    detail: "Requires repeated buggy and fixed revision evidence.",
    state: "locked",
  },
  {
    name: "maintainer_validated",
    label: "Maintainer validated",
    detail: "Requires independent human evidence outside the CLI.",
    state: "locked",
  },
] as const;

const securityControls = [
  ["Network", "Disabled during verification"],
  ["Filesystem", "Read-only root and workspace"],
  ["Identity", "Non-root UID/GID 65532"],
  ["Privileges", "All capabilities dropped"],
  ["Resources", "1 CPU · 1 GiB · 128 PIDs"],
  ["Fallback", "No native host execution"],
] as const;

const flow = [
  ["01", "Pin", "Canonical issue + exact SHA"],
  ["02", "Bound", "Safe archive + limited context"],
  ["03", "Screen", "One test + static policy"],
  ["04", "Verify", "Collect + repeat in Docker"],
  ["05", "Record", "Patch + replayable report"],
] as const;

export default function Home() {
  return (
    <main id="top">
      <header className="siteHeader">
        <a className="brand" href="#top" aria-label="ReproAssert home">
          <span className="brandMark" aria-hidden="true">
            RA
          </span>
          <span>ReproAssert</span>
        </a>

        <nav className="navLinks" aria-label="Primary navigation">
          <a href="#proof">Proof</a>
          <a href="#security">Security</a>
          <a href="#benchmark">Benchmark</a>
          <a href="#install">Install</a>
        </nav>

        <a className="button buttonDark headerCta" href={githubUrl}>
          View on GitHub
          <span aria-hidden="true">↗</span>
        </a>
      </header>

      <section className="hero pageSection" aria-labelledby="hero-title">
        <div className="heroCopy">
          <div className="eyebrow">
            <span className="statusDot" aria-hidden="true" />
            Open source · Python / pytest · alpha
          </div>
          <h1 id="hero-title">
            The test
            <br />
            before the <span className="accentWord">fix.</span>
          </h1>
          <p className="heroLead">
            Turn a public GitHub issue and an exact commit into a minimal test
            candidate, then verify its failure inside a locked-down Docker
            boundary—before anyone changes production code.
          </p>
          <div className="heroActions">
            <a className="button buttonAccent" href="#install">
              Run it locally
              <span aria-hidden="true">↓</span>
            </a>
            <a
              className="textLink"
              href={`${githubUrl}/tree/main/evidence/live-demo`}
            >
              Inspect the verified self-fixture
              <span aria-hidden="true">→</span>
            </a>
          </div>
          <p className="heroQualifier">
            Self-fixture verified. Current maximum claim: {" "}
            <code>repeatable_base_failure</code>. Historical benchmark: 0 / 20. No
            semantic-validity claim yet.
          </p>
        </div>

        <div className="terminalPanel" aria-label="Verified ReproAssert public self-fixture">
          <div className="terminalTopline">
            <div className="terminalLights" aria-hidden="true">
              <span />
              <span />
              <span />
            </div>
            <span>public issue #1 · strict profile v1</span>
            <span className="terminalReady">verified 2026-07-09</span>
          </div>
          <div className="terminalBody">
            <p className="terminalComment"># Public self-fixture. Generate no fix.</p>
            <pre>
              <code>
                <span className="prompt">$</span> reproassert issue \
                {"\n"}  https://github.com/Atomics-hub/reproassert/issues/1 \
                {"\n"}  --commit 7b03e8f7f4b7... \
                {"\n"}  --generator-command ./examples/deterministic_generator.py
              </code>
            </pre>

            <div className="terminalRule" />

            <div className="terminalResult">
              <div>
                <span>claim</span>
                <strong>repeatable_base_failure</strong>
              </div>
              <div>
                <span>collection</span>
                <strong>passed</strong>
              </div>
              <div>
                <span>base reruns</span>
                <strong>3 / 3 same fingerprint</strong>
              </div>
            </div>

            <pre className="artifactList">
              <code>
                <span className="terminalDim">patch</span>  evidence/live-demo/candidate.patch
                {"\n"}
                <span className="terminalDim">report</span> evidence/live-demo/reproassert-report.json
                {"\n"}
                <span className="terminalDim">replay</span> 3 / 3 same fingerprint
              </code>
            </pre>
          </div>
          <div className="terminalFoot">
            Self-owned fixture · fresh replay matched · not benchmark evidence
          </div>
        </div>
      </section>

      <section className="truthStrip" aria-label="Product contract summary">
        <div>
          <span className="truthLabel">Input</span>
          <strong>Issue URL + exact SHA</strong>
        </div>
        <div>
          <span className="truthLabel">Output</span>
          <strong>Test patch + JSON evidence</strong>
        </div>
        <div>
          <span className="truthLabel">Boundary</span>
          <strong>Docker only, network off</strong>
        </div>
        <div>
          <span className="truthLabel">Benchmark</span>
          <strong>0 / 20 scored</strong>
        </div>
      </section>

      <section className="pageSection proofSection" id="proof" aria-labelledby="proof-title">
        <div className="sectionHeading splitHeading">
          <div>
            <p className="kicker">Evidence before confidence</p>
            <h2 id="proof-title">A claim ladder with a hard stop.</h2>
          </div>
          <p>
            ReproAssert records what happened; it does not promote a consistent
            failure into semantic truth. Higher claims stay visibly locked until
            they earn different evidence.
          </p>
        </div>

        <ol className="claimLadder">
          {claimSteps.map((step, index) => (
            <li className={`claimStep claim-${step.state}`} key={step.name}>
              <div className="claimIndex">{String(index + 1).padStart(2, "0")}</div>
              <div className="claimCopy">
                <span className="claimCode">{step.name}</span>
                <h3>{step.label}</h3>
                <p>{step.detail}</p>
              </div>
              <span className="claimState">
                {step.state === "ceiling"
                  ? "current max"
                  : step.state === "locked"
                    ? "not produced"
                    : "implemented"}
              </span>
            </li>
          ))}
        </ol>
      </section>

      <section className="securitySection" id="security" aria-labelledby="security-title">
        <div className="pageSection securityInner">
          <div className="securityIntro">
            <p className="kicker kickerLight">Hostile by default</p>
            <h2 id="security-title">The repository is data until the sandbox says otherwise.</h2>
            <p>
              Issue prose is never copied into a command. Repository code and
              candidate tests execute only inside the strict verifier. A trusted
              generator adapter stays outside that boundary and receives only an
              explicit environment allowlist.
            </p>
            <a
              className="textLink textLinkLight"
              href={`${githubUrl}/blob/main/docs/threat-model.md`}
            >
              Read the threat model
              <span aria-hidden="true">↗</span>
            </a>
          </div>

          <div className="securityGrid">
            {securityControls.map(([label, value]) => (
              <div className="securityCard" key={label}>
                <span>{label}</span>
                <strong>{value}</strong>
              </div>
            ))}
          </div>

          <div className="riskNote">
            <span className="riskMark" aria-hidden="true">!</span>
            <p>
              <strong>Residual risk is explicit.</strong> Docker shares a kernel
              on Linux, test output can be adversarial, and a user-selected
              generator adapter is trusted host code. A repeated failure is
              bounded evidence—not proof of issue semantics or complete safety.
            </p>
          </div>
        </div>
      </section>

      <section className="pageSection benchmarkSection" id="benchmark" aria-labelledby="benchmark-title">
        <div className="benchmarkLedger">
          <div className="ledgerHeader">
            <div>
              <p className="kicker">Public benchmark ledger · v0.1</p>
              <h2 id="benchmark-title">Twenty frozen cases. Zero scored results.</h2>
            </div>
            <div className="ledgerScore" aria-label="Zero of twenty cases scored">
              <strong>0</strong>
              <span>/ 20</span>
            </div>
          </div>

          <div className="caseGrid" aria-label="Twenty pending benchmark cases">
            {Array.from({ length: 20 }, (_, index) => (
              <div className="caseCell" key={index}>
                <span>{String(index + 1).padStart(2, "0")}</span>
                <strong>pending</strong>
              </div>
            ))}
          </div>

          <div className="ledgerFooter">
            <p>
              <strong>This is preregistration, not performance.</strong> The
              manifest is frozen across 10 repositories. Every assigned case,
              including abstentions and infrastructure failures, stays in the
              denominator.
            </p>
            <a className="button buttonOutline" href={`${githubUrl}/tree/main/benchmarks/v0.1`}>
              Inspect the ledger
              <span aria-hidden="true">↗</span>
            </a>
          </div>
        </div>

        <div className="gateGrid">
          <div className="gateLead">
            <span>Continue only if the evidence trends toward all gates</span>
          </div>
          <div><strong>≥ 6 / 20</strong><span>semantically valid</span></div>
          <div><strong>&lt; 10 min</strong><span>median runtime</span></div>
          <div><strong>≈ $1</strong><span>median cost per success or measured path</span></div>
          <div><strong>1 + 3</strong><span>one validation, three willing to reuse</span></div>
        </div>
      </section>

      <section className="architectureSection" id="architecture" aria-labelledby="architecture-title">
        <div className="pageSection">
          <div className="sectionHeading splitHeading">
            <div>
              <p className="kicker">Thin by design</p>
              <h2 id="architecture-title">One narrow, inspectable loop.</h2>
            </div>
            <p>
              Provider-neutral generation feeds a deterministic controller. The
              controller owns every execution argument and every artifact path.
            </p>
          </div>

          <ol className="flowGrid">
            {flow.map(([number, title, detail]) => (
              <li key={number}>
                <span className="flowNumber">{number}</span>
                <h3>{title}</h3>
                <p>{detail}</p>
              </li>
            ))}
          </ol>

          <div className="artifactContract">
            <div>
              <span className="artifactNumber">A</span>
              <div>
                <code>candidate.patch</code>
                <p>One new pytest file. No production edits.</p>
              </div>
            </div>
            <div>
              <span className="artifactNumber">B</span>
              <div>
                <code>reproassert-report.json</code>
                <p>SHA, image, limits, exit codes, logs, fingerprints, hashes.</p>
              </div>
            </div>
            <div>
              <span className="artifactNumber">C</span>
              <div>
                <code>reproassert replay &lt;report&gt;</code>
                <p>Fresh fetch and controller-owned rerun from bounded data.</p>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="pageSection installSection" id="install" aria-labelledby="install-title">
        <div className="installCopy">
          <p className="kicker">Useful locally. Open source.</p>
          <h2 id="install-title">Start with the boundary, not a cloud account.</h2>
          <p>
            The alpha supports canonical public GitHub issues and Python/pytest.
            It does not install repository dependencies, access private
            repositories, or fall back to executing on your host.
          </p>

          <div className="installRequirements">
            <span>Python 3.10+</span>
            <span>uv or venv</span>
            <span>Docker</span>
          </div>

          <a className="button buttonDark" href={`${githubUrl}#install-from-source`}>
            Read the install guide
            <span aria-hidden="true">↗</span>
          </a>
        </div>

        <div className="installTerminal" aria-label="ReproAssert local installation commands">
          <div className="installTerminalHead">
            <span>local setup</span>
            <span>no hosted account</span>
          </div>
          <pre>
            <code>
              <span className="prompt">$</span> git clone {githubUrl}.git
              {"\n"}<span className="prompt">$</span> cd reproassert
              {"\n"}<span className="prompt">$</span> uv sync
              {"\n\n"}<span className="prompt">$</span> uv run reproassert sandbox build
              {"\n"}<span className="prompt">$</span> uv run reproassert doctor
            </code>
          </pre>
          <div className="doctorRows">
            <div><span>Docker CLI</span><strong>ready</strong></div>
            <div><span>Sandbox image</span><strong>required</strong></div>
            <div><span>Native fallback</span><strong>disabled</strong></div>
          </div>
        </div>
      </section>

      <section className="businessSection" aria-labelledby="business-title">
        <div className="pageSection businessInner">
          <div>
            <p className="kicker">Business hypothesis · not an offer</p>
            <h2 id="business-title">Hosted operations may be valuable. The free core stays useful.</h2>
          </div>
          <div className="businessMath">
            <span>Illustrative path only</span>
            <div>
              <strong>51</strong>
              <span>teams</span>
              <b>×</b>
              <strong>$199</strong>
              <span>/ month</span>
              <b>=</b>
              <strong>$10,149</strong>
              <span>MRR</span>
            </div>
            <p>
              Zero willingness-to-pay, conversion, retention, or margin evidence
              has been measured. Private-repo runners and billing wait for
              technical and maintainer gates.
            </p>
          </div>
        </div>
      </section>

      <section className="finalCta pageSection" aria-labelledby="final-title">
        <div>
          <span className="finalIndex">RA / 01</span>
          <h2 id="final-title">Don’t trust the fix.<br />Reproduce the failure.</h2>
        </div>
        <div className="finalCtaActions">
          <p>
            Inspect the code, the frozen benchmark, and the exact security
            boundary. Then run the open-source slice locally.
          </p>
          <a className="button buttonAccent buttonLarge" href={githubUrl}>
            Open ReproAssert on GitHub
            <span aria-hidden="true">↗</span>
          </a>
        </div>
      </section>

      <footer>
        <a className="brand footerBrand" href="#top">
          <span className="brandMark" aria-hidden="true">RA</span>
          <span>ReproAssert</span>
        </a>
        <p>Open-source local core · MIT licensed · Public alpha</p>
        <div>
          <a href={`${githubUrl}/blob/main/SECURITY.md`}>Security</a>
          <a href={`${githubUrl}/blob/main/docs/architecture.md`}>Architecture</a>
          <a href={githubUrl}>GitHub</a>
        </div>
      </footer>
    </main>
  );
}
