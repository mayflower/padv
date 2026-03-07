# padv Verbesserungspotenziale — Research Report

*Basierend auf der AdaLogics Software Security Paper List und aktueller Forschung (2024–2026)*

---

## Executive Summary

Die Analyse von ~250 Papers aus der AdaLogics-Sammlung und ergänzender aktueller Forschung identifiziert **7 konkrete Verbesserungsfelder** für padv. Die wichtigsten Hebel liegen in: LLM-augmentierter Taint-Spezifikation (IRIS/STaint-Ansatz), State-Aware Web Discovery (Enemy-of-the-State), Input-to-State Correspondence für Canary-Optimierung (REDQUEEN), und Agentic Concolic Execution für die Validation-Phase.

---

## 1. Discovery: LLM-augmentierte Taint-Spezifikationen

### Problem in padv
padv's statische Discovery (Source-Grep, Joern-CPG, SCIP) arbeitet mit vordefinierten Sink/Source-Listen. PHP-Anwendungen nutzen aber häufig Custom-Wrapper, ORM-Layer und Framework-spezifische Abstraktionen, die nicht in Standard-Spezifikationen enthalten sind.

### Relevante Papers & Techniken

**IRIS (LLM-Assisted Static Analysis, 2024)** — Nutzt LLMs um Taint-Spezifikationen automatisch zu inferieren. Statt manueller Sink/Source-Definitionen analysiert das LLM Funktionssignaturen und Code-Kontext, um zu entscheiden ob eine Funktion als Source, Sink oder Propagator fungiert. Ergebnis: 55 vs. 27 gefundene Vulnerabilities gegenüber CodeQL allein.

- Quelle: https://arxiv.org/abs/2405.17238

**STaint (ASE 2025)** — Direkt PHP-relevant. Nutzt LLM-assistierte bi-direktionale Taint-Analyse speziell für Second-Order-Vulnerabilities (z.B. stored XSS, SSRF via DB-Roundtrip). Das LLM identifiziert Custom-DB-Access-Funktionen und rekonstruiert Taint-Flows durch die Datenbank hindurch.

- Quelle: https://conf.researchr.org/details/ase-2025/ase-2025-nier-track/32/STaint

**Artemis (2025)** — Nutzt LLM-assistierte inter-prozedurale pfad-sensitive Taint-Analyse für SSRF-Detection in PHP. Führt "safety string assurance rules" ein um unmögliche Exploit-Pfade frühzeitig auszuschließen.

- Quelle: https://arxiv.org/pdf/2502.21026

**LLMxCPG (USENIX Security 2025)** — Kombiniert Code Property Graphs mit LLMs. CPG-basierte Slice-Konstruktion reduziert den Code um 67–91% bei Erhalt des vulnerability-relevanten Kontexts. Das LLM arbeitet dann nur auf dem relevanten Slice.

- Quelle: https://www.usenix.org/system/files/usenixsecurity25-lekssays.pdf

### Konkreter Verbesserungsvorschlag für padv

**A1: LLM-basierte Taint-Spec-Inference als Pre-Discovery-Phase**

Vor der eigentlichen Joern/SCIP-Analyse einen LLM-Pass einführen, der:
1. Custom Sources identifiziert (Framework-spezifische Request-Abstraktionen, ORM-Getter)
2. Custom Sinks findet (Wrapper um `exec()`, `eval()`, Custom-DB-Query-Builder)
3. Propagation-Regeln für Framework-spezifische Sanitizer ableitet
4. Die generierten Specs als Joern/SCIP-Konfiguration materialisiert

Dies würde die Candidate-Yield bei Framework-basierten PHP-Apps (Laravel, Symfony, WordPress-Plugins) signifikant erhöhen.

**A2: CPG-Slice → LLM-Refinement Pipeline (LLMxCPG-Ansatz)**

Statt den gesamten Codebase an DeepAgents zu geben, erst Joern-CPG-Slices entlang potentieller Taint-Pfade extrahieren (67–91% Reduktion), dann das LLM nur auf diesen Slices arbeiten lassen. Das verbessert sowohl Precision als auch Token-Effizienz der Agenten.

---

## 2. Web Discovery: State-Machine-Inference

### Problem in padv
Web-Discovery navigiert LLM-gesteuert durch die Anwendung und extrahiert Pfade/Parameter. Aber ohne Modell des Anwendungszustands kann die Navigation wichtige State-abhängige Pfade verpassen (z.B. Flows die nur nach bestimmten Voraussetzungen erreichbar sind).

### Relevante Papers

**Enemy of the State (USENIX Security 2012)** — Inferiert die State-Machine einer Webanwendung durch Black-Box-Navigation. Beobachtet Output-Differenzen um interne Zustandswechsel zu erkennen und baut daraus ein Zustandsmodell. Dieses Modell steuert dann die weitere Exploration, wodurch mehr Code exerciert und mehr Vulnerabilities gefunden werden als bei zustandsloser Navigation.

- Quelle: https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/doupe

**PULSAR (Protocol State Fuzzing)** — Stateful Black-Box-Fuzzing proprietärer Protokolle. Lernt Zustandsmaschinen aus beobachteten Nachrichten-Sequenzen.

### Konkreter Verbesserungsvorschlag für padv

**B1: State-Graph-Inference in Web-Discovery**

Den LLM-gesteuerten Browser-Navigator um ein explizites Zustandsmodell erweitern:
1. Playwright-Sessions beobachten Response-Differenzen (DOM-Changes, Cookie-Mutations, Session-Variablen)
2. Ein Zustandsgraph wird inkrementell aufgebaut
3. Die LLM-Priorisierung der nächsten URL nutzt den Zustandsgraphen um gezielte State-Transitions auszulösen
4. Frontier-Iteration nutzt den State-Graphen für gezielte Re-Exploration unbesuchter Zustände

Dies ist besonders relevant für Multi-Step-Workflows (z.B. Admin-Setup → Config-Change → Vulnerable-Endpoint).

---

## 3. Validation: Input-to-State Correspondence (REDQUEEN-Technik)

### Problem in padv
Die Validation-Phase erzeugt pro Kandidat genau 3 positive Requests mit einem eindeutigen Canary. Die Requests sind agentisch geplant, aber die Canary-Strategie ist statisch — es gibt kein systematisches Feedback darüber, *wie* der Input den internen Zustand beeinflusst.

### Relevante Papers

**REDQUEEN (NDSS 2019)** — Beobachtet, dass Input-Bytes oft direkt (oder nach einfachen Transformationen wie Byte-Swap, Base64) in Vergleichsoperanden der Programmausführung auftauchen. Durch "Colorization" (zufällige Bytes einfügen und in Comparison-Operanden wiederfinden) werden Magic-Number-Checks und Checksums automatisch überwunden — ohne teure symbolische Ausführung.

- Quelle: https://www.ndss-symposium.org/ndss-paper/redqueen-fuzzing-with-input-to-state-correspondence/

**IJON (S&P 2020)** — Ermöglicht menschliche Annotation von internen Zustandsvariablen, die der Fuzzer als Coverage-Feedback nutzt. Minimale Annotations (oft eine Zeile) erlauben das Lösen von Deep-State-Problemen.

- Quelle: https://nyx-fuzz.com/papers/ijon.pdf

### Konkreter Verbesserungsvorschlag für padv

**C1: Morcilla-gestütztes Input-to-State Feedback**

Morcilla instrumentiert bereits die PHP-Ausführung und liefert Call-Count, Payload, Correlation-Echo. Dieses Feedback könnte erweitert werden um:
1. **Canary-Tracking**: Nicht nur "reflektiert ja/nein", sondern *wo* und *wie transformiert* der Canary im Execution-Flow auftaucht (analog REDQUEEN-Colorization)
2. **Comparison-Operand-Reporting**: Welche Vergleiche auf dem Pfad zum Sink durchgeführt werden und welche Werte erwartet werden → automatische Ableitung besserer Payloads
3. **Conditional Coverage**: Welche Branches auf dem Intercept-Pfad genommen/nicht genommen wurden → gezieltere positive/negative Requests

Dies würde die 3 positiven Requests deutlich gezielter machen und könnte die Gate-V3 (Boundary/Signal Proof) Success-Rate erhöhen.

**C2: IJON-inspirierte Morcilla-Annotations**

Für komplexe Kandidaten (z.B. Multi-Step-Exploits) könnten Morcilla-Intercepts um IJON-artige State-Annotations erweitert werden: Der Agent definiert welche interne Variable als "Fortschritt" gilt, und das Gate-System nutzt dieses Signal zur Bewertung.

---

## 4. Validation: Concolic/Hybrid Execution für PHP

### Problem in padv
padv validiert rein über HTTP-Requests mit Morcilla-Beobachtung. Wenn ein Kandidat scheitert, gibt es wenig Information *warum* — welche Bedingung auf dem Pfad nicht erfüllt war.

### Relevante Papers

**AnimateDead (USENIX Security 2023)** — Ein PHP-Emulator für Concolic Execution. Ermöglicht Offline-Analyse ohne Produktions-Overhead. Debloated PHP-Apps sind 25–69% kleiner und exponiert gegenüber 35–65% weniger historischen CVEs.

- Quelle: https://www.usenix.org/conference/usenixsecurity23/presentation/azad

**COTTONTAIL (IEEE S&P 2026)** — LLM-driven Concolic Execution. Nutzt LLMs als Constraint-Solver für hochstrukturierte Inputs. Drei Innovationen: Structure-Aware Path Constraint Selection, LLM-Driven Constraint Solving, History-Guided Seed Acquisition. 30–41% bessere Coverage als Baselines.

- Quelle: https://arxiv.org/abs/2504.17542

**Agentic Concolic Execution (S&P 2026)** — Destilliert Program-Execution-Flow in Natural-Language-Constraints und nutzt einen autonomen Solving-Agent der semantisches Verständnis, Problem-Dekomposition und iteratives Tool-Calling kombiniert.

- Quelle: https://abhikrc.com/pdf/SP26.pdf

### Konkreter Verbesserungsvorschlag für padv

**D1: Lightweight Concolic Feedback für gescheiterte Validationen**

Wenn ein Kandidat V3 (Boundary/Signal Proof) nicht besteht, optional einen AnimateDead-artigen Concolic-Pass starten:
1. Den HTTP-Request-Pfad concolic durch den PHP-Code verfolgen
2. Path-Constraints extrahieren die zum Scheitern geführt haben
3. LLM (COTTONTAIL-Ansatz) generiert angepasste Requests die die Constraints erfüllen
4. Re-Validation mit den neuen Requests

Dies wäre ein gezielter "Rescue-Loop" für vielversprechende Kandidaten die am V3-Gate scheitern, statt sie direkt zu droppen.

**D2: Agentic Constraint Solving im Validation-Planer**

Den DeepAgent-Planer um die Fähigkeit erweitern, Morcilla-Feedback in natürlichsprachliche Constraints zu übersetzen (analog Agentic Concolic Execution) und daraus systematisch bessere Payloads abzuleiten.

---

## 5. Gate-System: Non-Distinguishable Inconsistencies (NDI)

### Problem in padv
Das Gate-System (V0–V6) ist deterministisch und evidence-basiert — ein großer Vorteil. Aber es fehlt ein systematischer Mechanismus um *semantische Inkonsistenzen* im Code zu erkennen, die über Taint-Flow-Matching hinausgehen.

### Relevante Papers

**NDI (CCS 2022)** — "Non-Distinguishable Inconsistencies as a Deterministic Oracle for Detecting Security Bugs." Wenn zwei Code-Pfade in einer Funktion inkonsistente Sicherheitszustände aufweisen (z.B. freed vs. initialized) die von Callern nicht unterscheidbar sind, ist das deterministisch ein Bug. Specification-free, unterstützt komplexe/neue Bug-Typen, minimiert Data-Flow-Analyse.

- Quelle: https://dl.acm.org/doi/abs/10.1145/3548606.3560661

**NEZHA (Differential Testing)** — Domain-unabhängiges differentielles Testen. Nutzt multiple Implementierungen als gegenseitige Orakel.

### Konkreter Verbesserungsvorschlag für padv

**E1: Inkonsistenz-basiertes Gate (V2.5)**

Zwischen V2 (Multi-Evidence) und V3 (Boundary Proof) ein NDI-inspiriertes Gate einfügen:
1. Analysiere ob der Kandidaten-Pfad und funktional äquivalente Pfade (z.B. gleiche Funktion, anderer Branch) inkonsistente Security-Properties haben
2. Wenn ja: Zusätzliche Evidence für Validation (Confidence-Boost)
3. Wenn der Kandidat *nur* über NDI-Signale auffällt aber kein Runtime-Signal hat: `NEEDS_DEEPER_ANALYSIS` statt sofortiger Drop

**E2: Differential Validation**

Für bestimmte Vulnerability-Klassen (z.B. AuthZ-Bypass) die Negative-Control (V4) um differentielle Tests erweitern: Gleicher Request mit verschiedenen Auth-Levels, systematischer Vergleich der Morcilla-Reports.

---

## 6. Discovery: Fuzzing-inspirierte Exploration

### Problem in padv
Die statische Discovery findet Kandidaten basierend auf bekannten Patterns. Aber ungewöhnliche Vulnerability-Muster (unerwartete Datenflüsse, Type-Confusion in PHP's dynamischem Typsystem) werden so möglicherweise nicht entdeckt.

### Relevante Papers

**NEUZZ (S&P 2019)** — Nutzt neuronale Netze um eine "smooth approximation" des Programm-Branch-Verhaltens zu lernen. Gradient-guided Mutations explorieren gezielt unbesuchte Branches.

- Quelle: https://arxiv.org/pdf/1807.05620

**VUzzer (Application-aware Evolutionary Fuzzing)** — Nutzt statische und dynamische Analyse-Features um Mutations gezielt auf "interesting" Input-Positionen zu lenken.

**KameleonFuzz** — Evolutionary Fuzzing speziell für Black-Box XSS Detection. Direkt relevant für padv's Web-Vulnerability-Fokus.

**HotFuzz** — Discovering Algorithmic Denial-of-Service Vulnerabilities durch automatisierte Fuzzing-Techniken.

### Konkreter Verbesserungsvorschlag für padv

**F1: Morcilla-Guided Mutation für Validation-Requests**

Statt nur 3 statisch geplante positive Requests zu verwenden, einen leichten Mutations-Loop einführen:
1. Initiale Requests vom Agenten planen lassen (wie bisher)
2. Morcilla-Feedback der ersten Requests analysieren (Branch-Coverage, Call-Count)
3. Gezielte Mutations ableiten (NEUZZ/REDQUEEN-inspiriert) die unbesuchte Branches auf dem Kandidaten-Pfad triggern
4. Bis Budget erschöpft oder V3 bestanden

Dies erhöht die Chance, dass die Validation den tatsächlichen Trigger-Pfad findet, ohne das Gesamt-Request-Budget signifikant zu erhöhen.

---

## 7. Persistenz & Lernfähigkeit: Cross-Run Intelligence

### Problem in padv
padv persistiert Candidates, Bundles, Runs und Frontier-State. Aber das Lernen über Runs hinweg ist auf die Frontier-Iteration beschränkt. Es gibt kein systematisches Lernen aus *gescheiterten* Validierungen.

### Relevante Papers

**Optimizing Seed Selection for Fuzzing / MoonShine** — Lernen aus Execution-Traces um bessere Seeds zu selektieren. Transfer von Laufzeit-Wissen auf neue Fuzzing-Kampagnen.

**Covrig** — Framework für Analyse von Code/Test/Coverage-Evolution. Tracking wie sich Vulnerability-Landschaft über Software-Versionen ändert.

**Shadow Symbolic Execution** — Symbolische Ausführung die gezielt auf Unterschiede zwischen Software-Versionen fokussiert.

### Konkreter Verbesserungsvorschlag für padv

**G1: Failure-Pattern-Learning**

Gescheiterte Validierungen systematisch analysieren und Muster extrahieren:
1. Warum scheitern Kandidaten am häufigsten? (V0? V3? V4?)
2. Welche Discovery-Signale korrelieren mit Gate-Failure?
3. Diese Patterns als Skeptic-Input nutzen: Kandidaten mit Failure-korrelierten Merkmalen früher verwerfen oder gezielter validieren

**G2: Cross-Target Transfer-Lernen**

Wenn padv mehrere PHP-Targets analysiert (z.B. verschiedene WordPress-Plugins), könnten erfolgreich validierte Patterns als "Template-Candidates" für ähnliche Code-Muster in neuen Targets dienen.

---

## Priorisierungsempfehlung

| # | Verbesserung | Aufwand | Impact | Abhängigkeiten |
|---|-------------|---------|--------|----------------|
| A1 | LLM Taint-Spec Inference | Mittel | Hoch | Neue Pre-Discovery-Stage |
| C1 | Morcilla Input-to-State Feedback | Mittel | Hoch | Morcilla-Extension |
| B1 | State-Graph Web Discovery | Hoch | Hoch | Playwright-Integration |
| F1 | Morcilla-Guided Mutation | Niedrig | Mittel | Nur Validation-Loop |
| D1 | Concolic Rescue-Loop | Hoch | Mittel | AnimateDead-Integration |
| E2 | Differential Validation | Niedrig | Mittel | Nur Gate-Erweiterung |
| G1 | Failure-Pattern-Learning | Niedrig | Mittel | Nur Analyse-Layer |
| A2 | CPG-Slice → LLM Pipeline | Mittel | Mittel | Joern-Integration |
| E1 | NDI-Gate | Mittel | Niedrig-Mittel | Statische Analyse |
| G2 | Cross-Target Transfer | Mittel | Niedrig | Multi-Target-Support |

**Top-3 Quick Wins:** F1 (Mutation-Loop), E2 (Differential Validation), G1 (Failure-Pattern-Learning)

**Top-3 High-Impact:** A1 (LLM Taint-Spec), C1 (Input-to-State Feedback), B1 (State-Graph)

---

## Quellen

- IRIS: https://arxiv.org/abs/2405.17238
- STaint: https://conf.researchr.org/details/ase-2025/ase-2025-nier-track/32/STaint
- Artemis: https://arxiv.org/pdf/2502.21026
- LLMxCPG: https://www.usenix.org/system/files/usenixsecurity25-lekssays.pdf
- Enemy of the State: https://www.usenix.org/conference/usenixsecurity12/technical-sessions/presentation/doupe
- REDQUEEN: https://www.ndss-symposium.org/ndss-paper/redqueen-fuzzing-with-input-to-state-correspondence/
- IJON: https://nyx-fuzz.com/papers/ijon.pdf
- AnimateDead: https://www.usenix.org/conference/usenixsecurity23/presentation/azad
- COTTONTAIL: https://arxiv.org/abs/2504.17542
- Agentic Concolic Execution: https://abhikrc.com/pdf/SP26.pdf
- NDI: https://dl.acm.org/doi/abs/10.1145/3548606.3560661
- NEUZZ: https://arxiv.org/pdf/1807.05620
- TChecker: https://www.cse.cuhk.edu.hk/~wei/papers/ccs22_tchecker.pdf
- AdaLogics Paper List: https://github.com/AdaLogics/software-security-paper-list
