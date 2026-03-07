# PRD: Agentische Security‑Analyse für laufende PHP‑Applikationen (CLI) mit LangGraph/Python, LangChain DeepAgents, Joern und Header‑gesteuerter Zend‑Extension

**Version:** 1.0
**Datum:** 2026‑03‑05
**Produktname (Arbeitsname):** `padv` (PHP Agentic Discovery & Validation)
**Formfaktor:** Command‑Line‑Tool (Python)
**Scope:** **Discovery**, **Detection**, **Validation**
**Explizit out of scope:** Reporting (Issues/Advisories), Auto‑Patching/PRs, Disclosure‑Automation

**Gegebene Bausteine (fix):**

* LangGraph zur Orchestrierung agentischer Graphen/Loops
* LangChain **DeepAgents** als Agent‑Harness innerhalb ausgewählter Nodes (Planung, Subagents, Kontextverwaltung) ([LangChain Docs][1])
* Claude Agent SDK in einzelnen LangGraph Nodes für „kleine agentische Aufgaben“ (z. B. Critique, Plan‑Skizzen)
* Joern ist via Python integriert und verfügbar (CPG/Flow/Callsite‑Information)
* Kubernetes agent-sdk für isolierte Sandboxes (Build/Deploy/Reset/Test/Validation)
* Zend‑Extension existiert: **Request‑Header** aktiviert Intercepts / legt zu interceptende Calls fest; **Response‑Header** enthält die mitgeschnittenen Calls (inkl. Argumenten), Canary‑Mechanik existiert und wird bereits genutzt

**Entwicklungsmodus:** Die Anwendung soll **mit Unterstützung von Claude Code und OpenAI Codex** entwickelt werden. (Codex CLI kann Repos lesen, ändern und Kommandos ausführen; Codex nutzt repo-/dir‑basierte Instruktionsdateien wie `agents.md`.) ([OpenAI Developers][2])

---

## 1) Problem & Zielbild

### 1.1 Problem

PHP‑Security‑Findings leiden klassisch an zwei Dingen:

1. **Kein Crash‑Oracle** (im Gegensatz zu Memory‑Safety‑Targets) → Validation ist oft „weich“ (Statuscodes, Log‑Heuristiken) und FP‑anfällig.
2. **Stateful Webapps** (Auth, Ownership, Workflow‑State) → viele Kandidaten sind ohne deterministische Preconditions nicht valide.

Ihr habt bereits einen starken Hebel dagegen: eine Zend‑Extension, die **pro Request** gezielt Sinks/Methoden interceptet und die Calls im Response‑Header zurückgibt – plus Canary. Das kann als **deterministisches Runtime‑Oracle** genutzt werden (Reachability/Boundary‑Hit/Influence‑Proof).

### 1.2 Zielbild

`padv` liefert als CLI:

* **Discovery:** generiert Kandidaten (Hypothesen) aus Code‑Semantik (Joern) + Kontext (Diff/Fix‑Seed/Repo).
* **Detection:** erzeugt technisch nachvollziehbare „Kandidatenakten“ (Entry, Callsite‑Nähe, Preconditions, erwartete Intercepts).
* **Validation:** führt kontrollierte HTTP‑Sequenzen gegen die laufende App in der Sandbox aus und entscheidet **ausschließlich** über harte Gates auf Basis:

  * Joern‑Evidenz (Static),
  * Zend‑Extension‑Header‑Evidenz (Runtime Intercepts + Canary),
  * Negative Controls,
  * Reproduzierbarkeit (N≥3 frische Runs).

**Output:** ausschließlich interne **Evidence Bundles** (maschinenlesbar + human‑lesbar), keine Issues/PRs.

---

## 2) Produktziele und Nicht‑Ziele

### 2.1 Ziele (Priorität absteigend)

**G1 – Validated Precision (FP‑Minimierung):**
Validated Findings sollen extrem selten falsch sein; Default ist „drop/needs setup“ statt „maybe“.

**G2 – Deterministische Validation über Header‑Oracle:**
Die Zend‑Extension‑Rückgabe ist primäres Runtime‑Signal (Reachability/Influence).

**G3 – Agentik nur dort, wo sie Nutzen bringt:**
LLMs planen/triagieren/entwerfen Experimente, aber „VALIDATED“ wird mechanisch gegated.

**G4 – Repro‑first:**
Jedes VALIDATED muss auf frischen Sandboxes reproduzierbar sein (N≥3) und Negative Controls enthalten.

### 2.2 Nicht‑Ziele

* Keine Auto‑Kommunikation nach außen.
* Kein Auto‑Patching/PR.
* Keine „exploit engineering“ Workflows; Canary‑Proof und Boundary‑Proof reichen.
* Kein unautorisiertes Scanning außerhalb der Sandbox‑Targets.

---

## 3) Zielnutzer / Use Cases

### 3.1 Personas

* AppSec Engineer (PR/Release Gate)
* Security Researcher (Variant‑Analysis)
* Platform Engineer (Sandbox/Policies)

### 3.2 Use Cases

1. **Variant‑First:** Eingabe: Fix‑Commit/Seed → finde Varianten und validiere mit Header‑Oracle.
2. **Delta‑First:** Eingabe: PR/Commit‑Range → nur diff‑nahe Kandidaten validieren.
3. **Batch‑Conservative:** Eingabe: Repo@SHA → sehr konservative Discovery, Top‑K Validated.

---

## 4) Functional Scope (v1)

### 4.1 Vulnerability‑Klassen (v1, empfohlen)

Aus Sicht des Header‑Oracles am dankbarsten (hohe deterministische Signale):

* **SQL boundary influence** (z. B. `mysqli_query` als zentraler Sink)
* **Outbound boundary influence** (HTTP clients)
* **File boundary influence** (file read/write, include/require)
* **Deserialization reachability/influence** (nur bis zum primitive, kein Gadget‑Building)

AuthZ/IDOR ist möglich, aber benötigt semantische Invariant‑Oracles (Principal‑Kontrast) und ist weniger „Sink‑crash‑artig“. V1 kann es als experimentelle Klasse führen, aber nicht als Hauptlieferant.

---

## 5) CLI‑Produktanforderungen

### 5.1 Kommandos (v1)

**MUSS:**

* `padv run`
  Führt einen vollständigen Run aus (Discovery→Detection→Validation) in einem gewählten Modus.
* `padv analyze`
  Nur Static Discovery/Detection (Joern), erzeugt Kandidaten, aber keine Validation.
* `padv validate`
  Validiert gegebene Candidate IDs (gezielt, wiederholbar).
* `padv sandbox`
  Hilfskommandos: deploy/reset/status/logs (operativ, ohne manuelle K8s‑Eingriffe).

**SOLLTE:**

* `padv list` / `padv show`
  Kandidaten und Evidence Bundles anzeigen (aus lokalem Evidence Store).
* `padv export`
  Evidence Bundles in definierte Formate exportieren (z. B. JSON + Attachments), weiterhin intern.

### 5.2 Modes

* `--mode variant|delta|batch` (Default: variant, wenn Seed vorhanden; sonst delta, wenn Diff vorhanden)

### 5.3 Konfiguration

`padv` lädt ein projektbezogenes Config‑File (Format teamintern definieren; v1: YAML oder TOML) mit:

* Target URL / Base path
* Auth/State Recipes (optional; sonst needs‑setup)
* Zend‑Extension Header Contract (Names, Format, limits)
* Canary Policy
* Joern Query Sets/Profiles
* Sandbox spec (K8s: namespace template, resource limits, reset hooks)
* Budgets (max requests, max sandbox time, max candidates)
* Output Store & Redaction

---

## 6) Zend‑Extension HTTP Contract (v1‑Anforderung)

Da die Extension bereits existiert, ist das Ziel: **konfigurierbarer Client‑Adapter**, nicht Änderung am Server.

### 6.1 Request‑Header (Instrumentation Control)

* Muss pro Request definieren können:

  * welche Funktionen/Methoden zu intercepten sind (Intercept Set)
  * optional: Capture Policy (z. B. args redacted/hashed)
  * optional: Correlation (Request/Sequence ID)

### 6.2 Response‑Header (Intercept Report)

* Muss maschinenlesbar sein (z. B. JSON oder Base64‑JSON).
* Minimal pro Call Record:

  * `name` (function/method)
  * `args` (oder args fingerprints)
  * optional: timestamp / counter
  * optional: callsite/stack signature (falls verfügbar)

### 6.3 Header‑Limit Handling

* `padv` muss Truncation/Overflow erkennen können und den Run als **invalid** markieren.
* `padv` muss Intercept Sets automatisch verkleinern können, wenn zu viel Noise entsteht (Candidate‑scoped minimal sets).

---

## 7) Canary‑Strategie (v1)

### 7.1 Canary Requirements

* Ein Canary ist **per Candidate/Run** eindeutig.
* Canary muss in Experiments gezielt injiziert werden (Parameter/Body/etc.).
* Matching muss definierte Normalisierungen unterstützen (konservativ; begrenzt).

### 7.2 Oracle Hit Definition (v1)

Ein Oracle Hit liegt vor, wenn:

* im Intercept Report ein Call aus dem Candidate‑Intercept Set vorkommt **und**
* Canary (oder zulässige Transformationsvariante) in einem relevanten Call‑Argument (oder Fingerprint‑Match) auftaucht.

Optionales Strengthening (SOLLTE):

* Canary muss im „kritischen Argument“ auftreten (z. B. Query‑String bei SQL), nicht nur in Nebenstrings.

---

## 8) Static Analysis Integration (Joern) – Rolle im System

Joern wird nicht als Validator genutzt, sondern für:

1. **Candidate Generation / Scoping:** Entry→Boundary‑Nähe, callsites, slices.
2. **Constraint Extraction:** welche Guards/Preconditions plausible Voraussetzungen sind.
3. **Variant/Delta Fokussierung:** Suche auf diff‑nahe oder fix‑ähnliche Stellen begrenzen.

**Key Requirement:** Joern‑Outputs müssen als strukturierte Resultsets referenzierbar sein (IDs/Hashes) und in Evidence Bundles auftauchen.

---

## 9) Agentische Architektur (LangGraph + DeepAgents + Claude Agent SDK)

### 9.1 Prinzip: „Agenten planen, Gates entscheiden“

* LLMs dürfen Kandidaten vorschlagen, kritisieren, Experimente planen.
* Ein mechanisches Gate‑Modul entscheidet VALIDATED/DROPPED/NEEDS_SETUP.

### 9.2 Rollen (konzeptionell)

* **Proposer:** erzeugt Kandidaten (aus Joern + Kontext)
* **Skeptic:** versucht Kandidaten zu falsifizieren (fordert Preconditions, reduziert Intercepts)
* **Planner:** erstellt Validation Plan (Sequenzen + Negativkontrollen)
* **Validator:** wertet Runs aus, wendet Gates an, dedupliziert

### 9.3 Einsatz von DeepAgents

DeepAgents dienen als „Agent harness“ für **komplexe, multi‑step** Teilaufgaben (Planung, Kontextverwaltung, Subagent‑Delegation). ([LangChain Docs][1])
**Vorgabe (v1):**

* DeepAgent nur für Proposer/Planner in Mode batch/variant (wenn Multi‑Step nötig).
* Für kleine, klar umrissene Tasks (z. B. Critique eines einzelnen Candidates) genügt Claude Agent SDK Node.

---

## 10) Validation Gates (normativ, v1)

**Nur wenn alle Gates erfüllt sind → VALIDATED.**

### V0: Scope & Safety

* Sandbox aktiv, Instrumentierung erlaubt, Budget eingehalten.
* Instrumentierungsheader ist nur in Sandbox zulässig (Policy).

### V1: Preconditions vollständig

* Auth/Role/State/Objekte deterministisch herstellbar.
* Sonst: `NEEDS_HUMAN_SETUP` (kein „maybe validated“).

### V2: Dual Evidence (Static + Runtime)

* Static: Joern liefert plausible Slice/Callsite‑Nähe für Candidate.
* Runtime: Intercept Report belegt, dass erwartete Sinks tatsächlich aufgerufen wurden (Reachability).

### V3: Canary Boundary Proof

* Oracle Hit: Canary in relevanten Sink‑Args gemäß Matching Policy.

### V4: Negative Controls

* Mindestens 1 Negativkontrolle führt **nicht** zu Oracle Hit.

### V5: Repro

* Mindestens 3 frische Sandbox‑Runs reproduzieren Positiv/Negativ‑Ergebnis.

### V6: Dedup/Top‑K

* Root‑Cause clustering; max K Validated pro Run.

---

## 11) Evidence Bundle Spec (v1)

### 11.1 Bundle Inhalte (MUSS)

* Candidate metadata: entrypoint, location(s), class, preconditions
* Static artifacts: Joern query set IDs + result hashes
* Dynamic artifacts:

  * HTTP sequence summary (abstrakt)
  * Intercept reports (sanitized/redacted) inkl. Canary match summary
  * Negative control evidence
* Repro proof: run IDs, sandbox image digests, seed versions
* Limitations: muss leer sein bei VALIDATED

### 11.2 Redaction Policy (MUSS)

Da Intercept Reports sensible Daten enthalten können:

* `padv` muss mindestens „store redacted by default“ können:

  * Canary‑Kontext + Fingerprints statt Vollstrings
  * optional: vollständige Raw‑Reports nur in streng geschütztem Modus

---

## 12) Sandbox Requirements (Kubernetes agent-sdk)

### 12.1 Sandbox Lifecycle

* build → deploy → readiness gate → seed/reset → run sequences → collect artifacts → teardown
* deterministischer Reset ist zwingend (DB/Cache/Files/Queues)

### 12.2 Network & Safety

* Default deny egress (nur interne Dependencies)
* Ressourcenlimits + Timeouts (pro candidate und pro run)
* Audit logs: welche Requests wurden gesendet, welche Intercepts empfangen

---

## 13) Software‑Architektur (Python CLI)

### 13.1 Module (v1)

* `cli/` – argument parsing, commands, exit codes
* `config/` – config schema, validation, defaults
* `orchestrator/` – LangGraph graphs (variant/delta/batch)
* `agents/` – deepagent prompts/config + Claude SDK node prompts
* `static/joern/` – query sets, adapters, result normalization
* `dynamic/sandbox/` – k8s agent-sdk adapter, lifecycle, artifacts
* `dynamic/http/` – http runner, auth recipes, request sequencing
* `oracle/` – zend-extension adapter: header injection + report parsing + matchers
* `gates/` – mechanical gate engine + dedup/top‑k
* `store/` – evidence store, artifact refs, redaction
* `eval/` – golden set harness + metrics extraction
* `logging/` – structured logs + audit trail

### 13.2 Plugin/Extension Points (SOLLTE)

* Vuln classes plug‑in: `class → intercept set → joern query set → validation plan template`
* Target profile plug‑in: framework‑specific heuristics, routes/auth recipes

---

## 14) Entwicklungsanforderungen: Umsetzung mit Claude Code & OpenAI Codex (CLI‑gestützte Agenten)

### 14.1 Grundsatz

Die PRD dient als „Source of Truth“. Coding‑Agenten bekommen Aufgaben in **kleinen, testbaren Increments**.

### 14.2 Codex‑Nutzung (für Implementierung)

* Codex CLI ist ein lokaler Coding‑Agent, der im gewählten Verzeichnis Dateien lesen, ändern und Kommandos ausführen kann. ([OpenAI Developers][2])
* Für verlässliche Steuerung wird ein repo‑lokales Instruktionsdokument verwendet. Codex CLI enumeriert `agents.md`‑Dateien entlang des Pfads und injiziert sie automatisch in den Kontext. ([OpenAI Developers][3])
* Codex verwendet Konfigurationslayer (user‑level und repo‑level) über `config.toml`. ([OpenAI Developers][4])

**PRD‑Vorgabe:** Das Repository enthält ein „Agent Instructions“-Dokument (für Codex: `agents.md`) mit:

* Architekturregeln (Module, keine side effects)
* No‑go’s (kein reporting, keine writes)
* Test‑First/Acceptance‑Criteria
* Definition der Bundles/Gates als unveränderliche Specs

### 14.3 Claude Code‑Nutzung (für Implementierung)

Claude Code wird als alternativer Coding‑Agent genutzt, vor allem für:

* Refactor‑/Cleanup‑Tasks
* Prompt‑/Policy‑Feinschliff (Skeptic/Planner Prompts)
* Test‑/Doc‑Erstellung

**PRD‑Vorgabe:** Claude Code erhält dieselben Inkremente und muss dieselben Acceptance‑Checks erfüllen.

### 14.4 „Agentic Development Protocol“ (MUSS)

Für jede Arbeitseinheit:

1. Spec‑Update (falls nötig) → 2) Tests/Fixtures → 3) Implementierung → 4) CLI‑E2E smoke → 5) Review checklist
   Keine großen „Big Bang“-Changes.

---

## 15) Test‑ & Evaluation Plan (v1)

### 15.1 Teststufen

* **Unit:** Oracle parsing, canary matching, gate engine, config validation
* **Integration:** Joern adapter (stubbed), Sandbox adapter (stubbed), HTTP runner with mocked headers
* **E2E:** in echter Sandbox:

  * mindestens ein kleines PHP target (intern), das definierte intercept hits erzeugt
  * 3× repro + negative controls

### 15.2 Qualitätsmetriken

* Validated precision (internes human review)
* Repro success rate (>= 99% für VALIDATED)
* Median time‑to‑validated pro Candidate
* Drop reason distribution (Preconditions / No hit / No neg control / Flaky)

---

## 16) Milestones / Epics (umsetzbar mit Coding‑Agenten)

### Epic 1: CLI Skeleton + Config + Evidence Store

* Commands: run/analyze/validate/sandbox
* Config schema + validation
* Evidence Bundle schema + redaction defaults

**DoD:** CLI läuft, erzeugt leere Bundles/artefacts in dry-run.

### Epic 2: Zend‑Oracle Adapter (Header In/Out) + Canary Matcher

* Request header injector (config‑driven)
* Response header parser (config‑driven)
* Canary matching + truncation detection

**DoD:** Deterministische Tests mit recorded headers; gate‑ready artifacts.

### Epic 3: Sandbox Adapter (K8s agent-sdk) + Reset/Seed Contract

* Deploy/reset/run orchestration
* Artifact capture (logs, headers)
* Repro loop (3 runs)

**DoD:** Ein Beispiel‑target kann 3× reproduzierbar ausgeführt werden.

### Epic 4: Joern Adapter + Query Sets + Candidate Generator

* Query set registry
* Candidate schema populated (entrypoint, expected intercepts)
* Delta/variant scoping hooks

**DoD:** `analyze` erzeugt Kandidaten auf realem Repo.

### Epic 5: LangGraph Orchestrator + Gates + Dedup/Top‑K

* variant/delta/batch graphs
* Proposer/Skeptic/Planner nodes (DeepAgents/Claude SDK)
* Mechanical gate engine

**DoD:** `run` produziert VALIDATED nur bei erfüllten Gates.

---

## 17) Definition of Done (v1)

v1 ist erfüllt, wenn:

1. `padv run` in Mode variant und delta funktioniert (mindestens 1 Target), batch konservativ optional.
2. VALIDATED wird ausschließlich durch Gates erzeugt (Static + Runtime intercept + canary + neg control + repro).
3. Evidence Bundles sind vollständig, redacted by default, reproduzierbar.
4. Kein Reporting/Patching existiert im Tool.
5. Die Zend‑Extension wird ausschließlich über HTTP Header genutzt (keine Änderungen an der Extension erforderlich).

---

## 18) Offene Entscheidungen (explizit zu klären, bevor Coding‑Agenten starten)

Diese Punkte müssen als Inputs in der Config‑Schema‑Definition festgezurrt werden (keine Codebeispiele, aber verbindliche Felder):

1. **Header‑Namen + Report‑Encoding** (JSON vs Base64‑JSON; chunking oder truncation signal)
2. **Minimaler Call Record Shape** (name/args/fingerprints; optional callsite)
3. **Reset/Seed Interface** (wie wird DB/State garantiert frisch?)
4. **Auth/State Recipes** (wie werden Rollen/Objekte deterministisch hergestellt?)
5. **Budget defaults** (max candidates, max requests, max time)

---

Wenn du willst, kann ich als nächstes (weiterhin ohne Code) zwei sehr konkrete Ergänzungen liefern, die Codex/Claude Code die Implementierung deutlich leichter machen:

1. **Ein vollständiges, normatives Config‑Schema** (Feldliste, Typen, Defaults, Validierungsregeln) inklusive Zend‑Header Contract und Canary Policy.
2. **Eine Gate‑Matrix pro Vuln‑Klasse** (SQL/File/Outbound/Deser): erforderliche Intercepts, erforderliche Canary‑Matches, verpflichtende Negative Controls, erforderliche Joern‑Evidenz.

[1]: https://docs.langchain.com/oss/python/deepagents/overview?utm_source=chatgpt.com "Deep Agents overview - Docs by LangChain"
[2]: https://developers.openai.com/codex/cli/?utm_source=chatgpt.com "Codex CLI"
[3]: https://developers.openai.com/cookbook/examples/gpt-5/codex_prompting_guide/?utm_source=chatgpt.com "Codex Prompting Guide"
[4]: https://developers.openai.com/codex/config-basic/?utm_source=chatgpt.com "Config basics"

