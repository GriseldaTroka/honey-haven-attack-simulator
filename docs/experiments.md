# Final Experiments and Demonstration Setup

This document describes the final experiment scenarios, the repeatable experiment flow,
evidence collection steps, and the demo sequence used for the diploma thesis.

Files of interest:

- `configs/experiments.json` — experiment definitions used by the runner
- `tools/experiment_runner.py` — orchestrates run -> collect -> evaluate
- `attack_simulator/eval` — metrics, reporting, and runner used to compare logs


## Final Attack Scenarios

Four controlled experiments are prepared:

1. Reconnaissance (`reconnaissance`)
   - Scenario name: `web_reconnaissance`
   - Objective: detect discovery/probing behavior

2. Authentication (`authentication`)
   - Scenario name: `authentication_attack`
   - Objective: detect multiple login attempts

3. Web Application (`webapp`)
   - Scenario name: `sql_injection_test`
   - Objective: detect injection-like inputs

4. Full Campaign (`full_campaign`)
   - Campaign name: `full_web_attack_simulation`
   - Objective: end-to-end attacker flow


## Experiment Environment (repeatable)

Before each experiment:

- Reset honeypot (use your honeypot's reset or restart scripts).
- Clear honeypot logs or archive them to a timestamped folder.
- Ensure the honeypot is receiving telemetry (check dashboard or tail logs).
- Ensure simulator can reach the honeypot (network, DNS).

All environment items should be recorded in the experiment notes.


## Running an Experiment (automated)

Use the runner to execute an experiment, copy logs and run evaluation:

```bash
python tools/experiment_runner.py --experiment reconnaissance
```

This will create an output directory under `experiments_output/` containing:

- `honeypot_log_before_*.jsonl` (if present)
- the simulator JSONL log (copied)
- `reports/` with JSON and HTML evaluation reports


## Evidence to collect

For each run collect:

- Simulator logs (`logs/*.jsonl`) — detailed request events
- Honeypot logs (JSONL) — telemetry and alerts
- Screenshots of the honeypot dashboard (timeline, sessions)
- The evaluation report (`reports/*.json`, `*.html`)


## Documentation template per experiment

Use the template below for each experiment and save it alongside reports.

- Input:
  - Scenario: `...`
  - Attacker profile: `...`
  - Number of requests (from simulator): `...`
  - Duration: `...`

- Process:
  - Steps executed (recon, auth attempts, injection)
  - Components involved

- Output:
  - Events captured
  - Alerts generated
  - Journey reconstruction outcome
  - Performance observations


## Demonstration Flow (live)

1. Introduce architecture and explain telemetry flow.
2. Start honeypot and confirm telemetry is active.
3. Run one scenario with `tools/experiment_runner.py` (or run simulator CLI manually).
4. Open the generated HTML report from `experiments_output/.../reports`.
5. Open timeline/session views on the honeypot dashboard and show correlation.
6. Explain detection metrics and conclusions.


## Next improvements

- Add automated screenshot capture of dashboard (Selenium/Playwright).
- Add more precise session correlation using cookies and headers.
- Add visual timeline charts inside the HTML report.
