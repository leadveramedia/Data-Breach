# Breach Notifier (US)

Self-hosted notifier that checks official US breach announcements and dark-web leak claims
(metadata only) and emails you on first detection.

## Setup

1) Create a virtualenv and install dependencies:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2) Create `.env` from the template and fill in Mailjet SMTP values:

```bash
cp .env.example .env
```

3) Run once:

```bash
python app.py
```

## Scheduling

For fast detection, run every 15 minutes via cron:

```bash
*/15 * * * * cd /path/to/Data\ Breach && /path/to/.venv/bin/python app.py
```

## GitHub Actions (daily)

This repo includes a daily GitHub Actions workflow at 12:00 UTC. Set these repo secrets:

- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USER`
- `SMTP_PASS`
- `SMTP_FROM_NAME`
- `SMTP_FROM_EMAIL`
- `SMTP_TO_EMAIL`

The workflow uses an Actions cache for `data/seen.json` so you only get first‑detection emails.
Adjust the cron schedule in `.github/workflows/daily.yml` if you want a different time.

## Notes

- The script uses a small local dedupe store at `data/seen.json` so you only get "first detection" emails.
- Findings with a time label use a 24‑hour window; date‑only announcements use a 1‑day window.
- Dark web collection is metadata-only (no dump download).
- State AG sources are currently California and Maine; add more states by adding URLs to `config.yaml`.

## Configuration

`config.yaml` lists all sources. You can add/remove sources or tune keywords.
