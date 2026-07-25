# PADV Effectiveness Baseline — Prompt 00

Erhoben am 2026-07-25. Es wurde in dieser Welle **keine Produktionslogik geändert**.

## 1. Ausgangslage

| | |
|---|---|
| Repository | `/data/src/ml/padv` |
| Branch | `main` |
| `HEAD` | `dff8a6a` — *fix: restore cli and precondition contracts* |
| Arbeitsbaum bei Messung | sauber (vorhandene WIP-Änderungen lagen währenddessen im Stash) |
| Morcilla-Quelle | `/data/src/ml/morcilla` @ `9cc8ec9` |
| Docker | Engine 29.6.1, Compose v5.3.0 |

## 2. Standardtestgate

`pytest -q -m "not integration"` auf dem sauberen Baum:

| Lauf | Ergebnis | Dauer |
|---|---|---|
| wie vorgefunden | **5 failed, 353 passed, 2 deselected** | 904,74 s (15:04) |
| mit `env -u COMPOSER_AUTH` | **358 passed, 2 deselected** | dito, SCIP-Teil 0,80 s |

Die fünf Fehler lagen ausschließlich in `tests/test_scip_adapter.py` und waren **kein
Codefehler**: die Umgebungsvariable `COMPOSER_AUTH` enthält kein gültiges JSON
(unquotierte Schlüssel), woran Composer im SCIP-Bootstrap scheitert. Ohne die
Variable bestehen alle 11 SCIP-Tests. Die echte Baseline ist damit
**358 bestanden, 2 deselected**.

Die zwei deselecteten Tests tragen den Marker `integration`
(`pyproject.toml:68`: *requires external services (Joern, SCIP, Morcilla, LLM API)*).

Langsamste Tests: `tests/test_deepagents_harness.py` dominiert mit 18–32 s pro Test;
die Top-10 allein machen rund 250 s aus.

## 3. Gepinnter Zielstand

| | |
|---|---|
| Repository | `https://github.com/webpwnized/mutillidae.git` |
| Commit | `84f2c00d9141dbb9e26a448c8288e651e0b5bb04` |
| Version | 2.12.7, 2026-06-22 |

**Das Tooling pinnt nicht.** `scripts/mutillidae_e2e.sh:214-215` ruft
`clone_or_update_repo` auf, das mit `--depth 1` klont und bestehende Checkouts per
`git fetch` + `git checkout <default-branch>` + `git reset --hard origin/<default-branch>`
auf den beweglichen Branch-Tip zwingt (Zeilen 43–55). Der oben genannte Commit ist
also der Stand vom 2026-07-25, keine vom Tooling erzwungene Fixierung. Messwerte sind
zwischen zwei Läufen an verschiedenen Tagen nicht vergleichbar.

## 4. Verifizierte Referenz-Fixture

Vollständig strukturiert in
[`tests/fixtures/effectiveness/mutillidae-sqli-user-info.json`](../../tests/fixtures/effectiveness/mutillidae-sqli-user-info.json).
Jeder Wert wurde am gepinnten Checkout gelesen, keiner geraten.

Kette:

```
src/user-info.php:50            $lUsername = $_REQUEST["username"]
  └─ src/user-info.php:169      $SQLQueryHandler->getUserAccount($lUsername, $lPassword)
       └─ src/classes/SQLQueryHandler.php:397-400   String-Konkatenation in "SELECT * FROM accounts WHERE username='...'"
            └─ src/classes/SQLQueryHandler.php:402  $this->mMySQLHandler->executeQuery($lQueryString)
                 └─ src/classes/MySQLHandler.php:326-328  executeQuery -> doExecuteQuery
                      └─ src/classes/MySQLHandler.php:229  $this->mMySQLConnection->query($pQueryString)   <-- SINK
```

Drei Punkte, die vom bisher angenommenen Bild abweichen:

1. **Der Sink ist `mysqli::query`, nicht `mysqli_query`.** `$mMySQLConnection` wird in
   `MySQLHandler.php:135` als `new mysqli(...)` gesetzt; der Aufruf in Zeile 229 ist ein
   Methodenaufruf. Der Query-String ist **Argument 0**.
   `padv/static/joern/query_sets.py:28` führt `mysqli::query` bereits, die Interceptliste
   kann den Fall also ausdrücken.
2. **Die Route erfordert eine Anmeldung.** `src/index.php:481-485` listet `user-info.php`
   in `$lPagesRequiringAuthentication` und leitet ohne Session mit 302 auf `login.php` um.
   Ein Direktaufruf von `/user-info.php` ist ebenfalls nicht möglich, da die Datei
   `$SQLQueryHandler` voraussetzt, den nur `index.php:190` konstruiert. Die Fixture nennt
   das gesetzte Konto `jeremy` / `password` aus `src/set-up-database.php:213`.
3. **Security-Level 0 ist die Voraussetzung für Injizierbarkeit** (`index.php:26-27` als
   Default). Erst dort ist `stopSQLInjection` false und `user-info.php` liest `$_REQUEST`
   statt `$_POST`, sodass die Payload per GET transportiert werden kann.

## 5. Realer Morcilla-Handshake — der zentrale Befund

Gebaut wurde ein minimales `php:apache`-Image mit der echten Extension aus
`/data/src/ml/morcilla` @ `9cc8ec9`, identisch zum Verfahren in
`docker/mutillidae/www-morcilla.Dockerfile`.

Anfrage mit `Morcilla-Key`, `Morcilla-Intercept` und `Morcilla-Correlation`.
Vollständige Antwortheader:

```
HTTP/1.1 200 OK
Date: Sat, 25 Jul 2026 11:32:38 GMT
Server: Apache/2.4.68 (Debian)
X-Powered-By: PHP/8.5.8
X-Morcilla-Result: W3siZnVuY3Rpb24iOiJQcm9iZTo6cXVlcnkiLCJmaWxlIjoiL3Zhci93d3cvaHRtbC9wcm9iZS5waHAiLCJsaW5lIjo1LCJhcmdzIjpbIlwicGFkdi1jYW5hcnktYWJjMTIzXCIiXX1d
Content-Length: 9
Content-Type: text/html; charset=UTF-8
```

Dekodiert:

```json
[{"function":"Probe::query","file":"/var/www/html/probe.php","line":5,"args":["\"padv-canary-abc123\""]}]
```

Der Report selbst ist einwandfrei: Funktion, Datei, Zeile und der exakte Canary im
Argument. **Aber die Extension sendet genau einen Header.** PADV konfiguriert sechs
(`padv.mutillidae.strict.toml:9-15`):

| PADV erwartet | von Morcilla gesendet |
|---|---|
| `X-Morcilla-Result` | **ja** |
| `X-Morcilla-Status` | nein |
| `X-Morcilla-Call-Count` | nein |
| `X-Morcilla-Overflow` | nein |
| `X-Morcilla-Arg-Truncated` | nein |
| `X-Morcilla-Result-Truncated` | nein |
| `X-Morcilla-Correlation` | nein |

`php_morcilla.h:14` definiert `X-Morcilla-Result` als einzigen Ausgabeheader.
`Morcilla-Correlation` wird von PADV zwar gesendet (`morcilla.py:58`), von der Extension
aber weder gelesen noch zurückgespiegelt — `morcilla.c:489-498` liest ausschließlich
`HTTP_MORCILLA_KEY` und `HTTP_MORCILLA_INTERCEPT`.

Konsequenz, gemessen mit dem Baseline-Code gegen exakt diese Header:

```
status         : inactive
call_count     : 0
correlation_id : None
calls parsed   : 1 -> Probe::query
args           : ['"padv-canary-abc123"']
evidence.status: inactive
V0 verdict     : ('DROPPED', 'V0', 'runtime not in valid scope')
```

`parse_intercept_report` fällt für `status` auf den Default `"inactive"` zurück
(`padv/oracle/morcilla.py:145`), und `"inactive"` steht in `_evaluate_v0_scope` in
`hard_scope_failures` (`padv/gates/engine.py:42-44`). **Jeder reale Morcilla-Lauf wird an
V0 verworfen, bevor irgendein Witness geprüft wird.** Der Interceptbericht wird korrekt
geparst und dann nie benutzt.

Damit gilt: PADV hat gegen die echte Extension noch nie etwas runtime-validiert. Alle
grünen Runtime-Tests speisen synthetische Header ein, die die Extension nicht erzeugt.

### Weitere verifizierte Eigenschaften der Extension

- **Matching:** Schlüssel ist `<klasse>::<funktion>` bzw. `<funktion>`, kleingeschrieben
  (`morcilla.c:213-238`). `mysqli::query` ist damit adressierbar.
- **Interne Methoden werden interceptet.** Gegenprobe: `DateTime::format` und
  `ArrayObject::count` erschienen im Report. `mysqli::query` ist also erreichbar.
- **Interne Funktionen werden interceptet**, sofern sie nicht opcode-spezialisiert sind:
  `md5` und `str_repeat` erschienen, `strlen` nicht.
- **Truncation ist in-band, nicht im Header:** Strings über 251 Byte erhalten ein
  angehängtes `...` innerhalb von `args[]` (`morcilla.c:101-110`, `MORCILLA_MAX_ARG_LEN 256`).
  PADV liest Truncation ausschließlich aus Headern und erkennt sie folglich nie.
- **Limits:** `MORCILLA_MAX_CALLS 4096`, `MORCILLA_MAX_ARG_LEN 256`.
- Der erwartete `SELECT` ist rund 70 Zeichen plus Canary und bleibt sicher unter dem
  Argumentlimit.

## 6. Bestehende Messlücken

Ohne Produktionscode zu reparieren festgehalten:

1. **Oracle-Vertrag klafft auseinander** (Abschnitt 5). Entweder muss Morcilla die fünf
   fehlenden Header emittieren und die Korrelation zurückspiegeln, oder PADVs
   Oracle-Vertrag muss auf das reduziert werden, was die Extension liefert. Das ist eine
   Architekturentscheidung, keine Reparatur, die ich ohne Auftrag treffen sollte.
2. **Kein Pinning** des Benchmarktargets (Abschnitt 3).
3. **Korrelation ist nicht durchsetzbar.** Der Pack verlangt exakte
   Request-/Response-Korrelation; die Extension kennt das Konzept nicht.
4. **Truncation ist unerkennbar**, weil sie nur in-band signalisiert wird.
5. **`mysqli_query` vs. `mysqli::query`:** Testfixtures und Konfiguration im Repo gehen
   überwiegend vom prozeduralen Namen aus, der reale Sink ist der Methodenname.
6. **Die Fixture ist auth-pflichtig**, d. h. der Referenzfall braucht zwingend einen
   Login-Vorlauf und ist nicht mit einem einzelnen anonymen Request abbildbar.
7. **Umgebung:** `COMPOSER_AUTH` ist ungültiges JSON und lässt fünf Tests scheitern.

## 7. Ergebnis von Prompt 00

**NICHT BESTANDEN.**

Erfüllt sind: dokumentiertes Standardtestgate, commitgenaue und vollständig
strukturierte Fixture, erfolgreich geparster echter Morcilla-Report.

Nicht erfüllt ist die Abnahme *„Ein echter Morcilla-Report der bekannten Fixture wurde
erfolgreich geparst"* im Sinne eines für PADV verwertbaren Laufs. Der Blocker ist kein
Infrastrukturfehler, sondern ein Vertragsdefekt:

> Die Morcilla-Extension @ `9cc8ec9` sendet ausschließlich `X-Morcilla-Result`.
> PADV benötigt zusätzlich `X-Morcilla-Status`, `X-Morcilla-Correlation`,
> `X-Morcilla-Call-Count`, `X-Morcilla-Overflow`, `X-Morcilla-Arg-Truncated` und
> `X-Morcilla-Result-Truncated`. Ohne `X-Morcilla-Status` gilt jeder Lauf als
> `inactive` und wird an V0 als `runtime not in valid scope` verworfen.

Der volle Mutillidae-Stack wurde bewusst nicht hochgefahren: sein Ergebnis ist durch
diesen Befund bereits determiniert. Prompt 01 wurde nicht begonnen.

## 8. Nachtrag — Vertragsdefekt behoben

Auf Entscheidung des Benutzers wurde Variante 1 gewählt: die Extension emittiert die
fehlenden Header, statt PADVs Vertrag abzuschwächen. Geändert wurden
`/data/src/ml/morcilla/morcilla.c` und `php_morcilla.h` (**nicht committet**).

Neu emittiert, sobald eine Anfrage einen `Morcilla-Key` trägt — auch im Fehlerfall,
denn ein leerer Headersatz kann „nichts beobachtet" nicht von „nie beobachtet"
unterscheiden:

| Header | Wert |
|---|---|
| `X-Morcilla-Status` | `active_hits`, `active_no_hits`, `auth_failed`, `missing_intercept` |
| `X-Morcilla-Call-Count` | Anzahl aufgezeichneter Calls |
| `X-Morcilla-Overflow` | `true`, sobald `MORCILLA_MAX_CALLS` erreicht wurde |
| `X-Morcilla-Arg-Truncated` | `true`, sobald ein Argument gekürzt wurde |
| `X-Morcilla-Result-Truncated` | `true`, wenn der Payload `MORCILLA_MAX_RESULT_B64` (8192) überschreitet und deshalb weggelassen wird |
| `X-Morcilla-Correlation` | Echo von `Morcilla-Correlation` |

Trägt eine Anfrage keinen `Morcilla-Key`, bleibt die Antwort unverändert und
vollständig unmarkiert.

Der Korrelationswert stammt aus einem Requestheader und wird vor dem Echo auf
druckbares ASCII gefiltert und auf 128 Zeichen begrenzt, damit er keinen Header
injizieren kann.

Abgesichert durch [`tests/test_morcilla_extension_contract.py`](../../tests/test_morcilla_extension_contract.py)
(Marker `integration`): baut die echte Extension, stellt echte Requests und prüft den
Vertrag bis einschließlich V0. Vor der Änderung 7 von 9 Tests rot, danach 9 grün.

Damit ist der Blocker aus Abschnitt 7 aufgehoben. Offen bleiben die übrigen Messlücken
aus Abschnitt 6, insbesondere das fehlende Pinning des Benchmarktargets.
