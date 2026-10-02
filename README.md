# Attack Simulator

Attack Simulator is a controlled HTTP traffic generator for academic security research and local honeypot evaluation. It runs bounded reconnaissance, authentication, SQL injection, and API probing simulations against a configured lab target and records structured JSONL evidence.

The project is intended for systems you own or are explicitly authorized to test. The default target is loopback (`http://127.0.0.1:8000`) for a local Honey Haven instance. It must not be used to scan or attack arbitrary third-party systems.

## Purpose and Honey Haven relationship

Attack Simulator generates predictable, repeatable simulated attacker traffic for the Honey Haven honeypot project. Honey Haven receives the HTTP requests and produces its own telemetry. The optional experiment runner then copies a Honey Haven JSONL log and compares it with the simulator log using the evaluator in `attack_simulator/eval`.

The simulator does not contain a Honey Haven server, reset workflow, authentication service, or remote log collector. Start Honey Haven separately, point the simulator at its local HTTP listener, and provide the local Honey Haven telemetry log when running an evaluation.

## Architecture

```text
JSON configuration
	|
	v
CLI / local UI bridge ---> ScenarioController ---> attack modules ---> AttackHttpClient ---> local Honey Haven
	|                         |                       |
	|                         +-----------------------+----> JSONL logs
	v
React/Vite console                                      evaluator ---> JSON/HTML reports
```

Main components:

- `attack_simulator/config.py` loads JSON profiles, module defaults, scenarios, and campaigns.
- `attack_simulator/controller.py` coordinates ordered scenario and campaign phases.
- `attack_simulator/http_client.py` sends configured HTTP requests, maintains optional cookies, and records responses.
- `attack_simulator/modules/` contains reconnaissance, bounded brute-force, SQL injection, and API probe modules.
- `attack_simulator/profiles.py` defines browser-like and scanner-like request profiles.
- `attack_simulator/logging_utils.py` writes flushed JSONL event logs.
- `attack_simulator/eval/` compares simulator events with Honey Haven telemetry and creates reports.
- `attack_simulator/ui_service.py` exposes a loopback-only local bridge for the React console.
- `frontend/` contains the optional React/Vite operations console.
- `tools/experiment_runner.py` automates simulator execution, Honey Haven log collection, and evaluation.

## Technologies

- Python 3.10 or newer
- Python standard library HTTP and JSON tooling
- React and Vite for the optional local console
- JSON configuration and JSONL runtime evidence

The Python package has no third-party runtime dependencies. Frontend dependencies are declared in `frontend/package.json` and locked in `frontend/package-lock.json`.

## Available simulations

### Modules

- `reconnaissance`: bounded browsing and discovery requests.
- `brute_force`: bounded username/password combinations against the configured login endpoint.
- `sql_injection`: configured injection-like values in query, form, and endpoint-list scenarios.
- `api_probe`: discovery, interaction, decoy, and persistent follow-up requests.

### Scenarios

The example configuration includes `browser_api_probe`, `scanner_api_probe`, `persistent_api_probe`, `baseline_chain`, and `scanner_only`.

### Campaigns

The example configuration includes `web_reconnaissance` and `full_web_attack_simulation`.

Scenario and campaign definitions are in `configs/example_campaign.json`. Payloads, paths, delays, request limits, headers, and phase order are all configured there.

## Installation

Clone the repository and create a virtual environment if desired:

```bash
python -m venv .venv
```

Activate it on Windows PowerShell with `\.venv\Scripts\Activate.ps1`, or on macOS/Linux with `source .venv/bin/activate`.

Install the Python package in editable mode:

```bash
python -m pip install --upgrade pip
python -m pip install -e .
```

Install the optional frontend:

```bash
npm --prefix frontend install
```

## Configuration

The reproducible local configuration is `configs/example_campaign.json`:

- `target.base_url`: Honey Haven's local HTTP base URL. The safe default is `http://127.0.0.1:8000`.
- `default_timeout_seconds`: HTTP timeout for each request.
- `logging.output_dir`: simulator JSONL output directory, normally `logs`.
- `profiles`: browser-like or scanner-like headers, cookies, user agent, and lab source IP metadata.
- `module_defaults`: reusable request paths, payloads, limits, and delays.
- `scenarios`: ordered module sequences.
- `campaigns`: named multi-phase journeys and optional target environment metadata.

Edit the example configuration for a local Honey Haven port or use a separate local JSON configuration file. Do not commit credentials, tokens, private data, or production targets.

For experiment evaluation, set `HONEY_HAVEN_LOG_PATH` to a local Honey Haven JSONL log. `tools/experiment_runner.py` uses it when set and otherwise uses the portable default `honeypot_logs/honey-web.log`. See `.env.example` for the documented variable.

## Running the simulator

Run the baseline chain:

```bash
python -m attack_simulator --config configs/example_campaign.json run --scenario baseline_chain
```

Run the full campaign:

```bash
python -m attack_simulator --config configs/example_campaign.json campaign --campaign full_web_attack_simulation
```

Run one module:

```bash
python -m attack_simulator --config configs/example_campaign.json module reconnaissance
```

The command prints a summary and writes a timestamped JSONL file under `logs/`. Each event contains the module, scenario, method, target URL, status, latency, execution status, and bounded response preview. Runs require the configured Honey Haven HTTP listener to be available; connection failures are recorded in the log and cause a failed module result.

## Local web console

Start the loopback bridge from the repository root:

```bash
python -m attack_simulator.ui_service
```

In another terminal, start the frontend:

```bash
npm --prefix frontend run dev -- --host 127.0.0.1 --port 5174
```

Open `http://127.0.0.1:5174`. The frontend proxies `/api` requests to the bridge at `http://127.0.0.1:8765`. Keep both services bound to loopback for local lab use.

## Evaluation and expected output

When a Honey Haven JSONL telemetry log is available:

```bash
python -m attack_simulator evaluate --sim-log logs/<simulator-run>.jsonl --hp-log C:\path\to\HoneyHaven\logs\honey-web.log --out evaluation_reports --label baseline-chain
```

The evaluator writes JSON and HTML reports containing detection, logging, journey, and performance metrics. The experiment runner can automate a configured flow:

```bash
python tools/experiment_runner.py --experiment reconnaissance
```

The repository intentionally excludes generated logs, telemetry, reports, virtual environments, caches, and frontend installation output. These are produced locally during a run and should be archived separately when they contain approved research evidence.

## Testing and checks

There is currently no dedicated automated test suite in the repository. Recommended checks for a fresh clone are:

```bash
python -m compileall attack_simulator tools
python -m attack_simulator --config configs/example_campaign.json
npm --prefix frontend install
npm --prefix frontend run build
```

For an end-to-end smoke test, start Honey Haven locally, run `baseline_chain`, confirm the JSONL log is created, and compare it with Honey Haven telemetry using the evaluation command above. If Honey Haven is not running, simulator requests will fail by design; that is an unavailable integration target, not a successful integration test.

## Safety and authorized use

This is a security-testing simulator for a controlled academic project. Use it only against localhost, an isolated lab, Honey Haven, or another system for which you have explicit authorization. Keep request limits and delays appropriate for the lab. Do not add arbitrary-target discovery, credential theft, persistence, destructive actions, or functionality intended to compromise real third-party systems. Never commit real credentials, tokens, private keys, captured user data, or production telemetry.

## Academic context

The project supports repeatable security research and honeypot evaluation by correlating generated HTTP activity with Honey Haven telemetry. Configuration and generated event logs provide an auditable record of the simulated attack journey without requiring access to real-world targets.
