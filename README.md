# Clearance

A new Go vulnerability lands. Clearance tells you, for every service in your fleet, whether it is
**affected** (with the call path into the vulnerable function and the team that owns that code) or
**not affected** (with the proof: no path), and writes the OpenVEX statement for it.

The fleet, the dependencies, the advisories and the call paths live in a FalkorDB graph. The verdicts
are graph queries, so without the graph there is no answer.

Built during Graph Hacks (WeMakeDevs x FalkorDB), Oct 15-18 2026. Work in progress.

## Run it locally

```sh
docker compose up -d   # FalkorDB 6.0.2 on 6379, Browser on http://localhost:3000
npm install
cp .env.example .env
```
