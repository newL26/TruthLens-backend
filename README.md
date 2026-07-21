# TruthLens AI

**AI-Powered Misinformation & Scam Early-Warning Platform**

> Designed for Tanzania and East Africa. Powered by IBM watsonx.ai & IBM Granite.

---

## Overview

TruthLens AI is a production-quality web application that helps users identify potentially misleading information, misinformation, fake news, online scams, phishing attempts, and suspicious URLs using a multi-agent AI pipeline.

### Key Features (Phase 1)
- **7-Agent AI pipeline**: Content → Scam → URL → Risk → Explanation
- **Explainable results**: Risk score (0–100), threat category, key findings, actionable recommendations
- **JWT authentication** with refresh token rotation and blacklisting
- **Community reporting**: Submit suspicious content, duplicate detection
- **Threat campaigns**: Aggregated early-warning intelligence
- **IBM watsonx.ai** integration with seamless mock fallback for development

---

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Angular 17 (standalone), TailwindCSS |
| Backend | Python 3.11, Django 4.2, Django REST Framework |
| Auth | JWT (djangorestframework-simplejwt) |
| Database | PostgreSQL (SQLite for development/tests) |
| AI | IBM watsonx.ai + IBM Granite (mock provider for dev) |
| Queue | Celery + Redis (Phase 2+) |

---

## Project Structure

```
truthlens-backend/
├── config/             # Django settings, URLs, Celery
├── apps/
│   ├── accounts/       # Custom User model, JWT auth
│   ├── analysis/       # Core analysis models & API
│   └── community/      # Reports, campaigns, audit log
├── agents/             # AI agents (content, URL, scam, risk, explanation)
├── services/           # AI provider abstraction (watsonx + mock)
├── utils/              # Audit logging helpers
└── tests/              # Integration + unit tests

truthlens-frontend/
└── src/app/
    ├── core/           # Services, guards, interceptors, models
    ├── shared/         # Reusable components (navbar, badge, gauge)
    └── features/       # Pages: landing, analyzer, results, auth, history
```

---

## Quick Start

### Backend

```bash
cd truthlens-backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Copy and configure env
cp .env.example .env
# Edit .env: set SECRET_KEY, DATABASE_URL

# Database setup (PostgreSQL)
createdb truthlens_db
python manage.py migrate
python manage.py createsuperuser

# Run development server
python manage.py runserver
```

For tests (uses SQLite, no PostgreSQL required):
```bash
DJANGO_SETTINGS_MODULE=config.test_settings python manage.py test tests --verbosity=2
```

### Frontend

```bash
cd truthlens-frontend
npm install
ng serve
# Open http://localhost:4200
```

---

## Environment Variables

See [`truthlens-backend/.env.example`](truthlens-backend/.env.example) for all variables.

Critical variables:
```env
SECRET_KEY=<your-secret-key>
DATABASE_URL=postgresql://user:pass@localhost:5432/truthlens_db
AI_PROVIDER=mock         # or: watsonx
WATSONX_API_KEY=...      # IBM watsonx.ai API key
WATSONX_PROJECT_ID=...   # IBM watsonx.ai project ID
WATSONX_MODEL_ID=ibm/granite-13b-chat-v2
```

---

## API Endpoints (Phase 1)

### Authentication
```
POST /api/v1/auth/register/          Register new user
POST /api/v1/auth/login/             Obtain JWT tokens
POST /api/v1/auth/logout/            Blacklist refresh token
POST /api/v1/auth/token/refresh/     Refresh access token
GET  /api/v1/auth/profile/           User profile
PATCH /api/v1/auth/profile/          Update profile
POST /api/v1/auth/change-password/   Change password
```

### Analysis
```
POST /api/v1/analysis/analyze/       Submit text/URL for analysis
GET  /api/v1/analysis/               List user analyses (auth required)
GET  /api/v1/analysis/{id}/          Get specific analysis result
```

### Community
```
POST /api/v1/community/report/       Submit scam report
GET  /api/v1/community/campaigns/    List threat campaigns
GET  /api/v1/community/campaigns/{id}/ Campaign detail
```

---

## IBM Technology Integration

| Service | Purpose |
|---|---|
| **IBM watsonx.ai** | Text generation for content analysis and explanations |
| **IBM Granite** | Foundation model (ibm/granite-13b-chat-v2) |
| **IBM Cloud Object Storage** | File uploads (Phase 5) |
| **IBM Cloud** | Deployment target (Phase 5) |

### AI Provider Abstraction

The `services/ai_provider.py` module abstracts the AI backend:
- `MockAIProvider` — deterministic synthetic responses (dev/test)
- `WatsonxProvider` — real IBM watsonx.ai calls

Switch by setting `AI_PROVIDER=watsonx` in `.env`.

---

## Risk Scoring Model

The Risk Assessment Agent combines 6 signals with configurable weights:

| Signal | Default Weight |
|---|---|
| Content Analysis | 20% |
| Source Reliability | 20% |
| Evidence Verification | 25% |
| URL Risk | 15% |
| Community Reports | 10% |
| Scam Pattern Detection | 10% |

**Note**: These weights are configurable in `settings.RISK_SCORE_WEIGHTS` and are not scientifically validated. The analysis is advisory only.

---

## Risk Levels

| Score | Level | Label |
|---|---|---|
| 0–15 | trustworthy | Likely Trustworthy |
| 16–30 | mostly_trustworthy | Mostly Trustworthy |
| 31–50 | needs_verification | Needs Verification |
| 51–65 | suspicious | Suspicious |
| 66–79 | high_risk | High Risk |
| 80–89 | scam | Potential Scam |
| 90–100 | misinformation | Potential Misinformation |

---

## Development Phases

- **Phase 1** [COMPLETE] — Backend, auth, text/URL analysis, Angular UI, result dashboard
- **Phase 2** — Screenshot upload, OCR, evidence retrieval, explainable AI
- **Phase 3** — Community reporting, similar content detection, threat campaigns
- **Phase 4** — Admin dashboard, analytics, threat map
- **Phase 5** — IBM Cloud deployment, production security, competition demo

---

## Responsible AI

TruthLens AI is built on responsible AI principles:
- Results are advisory only — never final verdicts
- Explainable scores with transparent agent weights
- No PII stored unnecessarily
- Community data anonymized
- Clear disclaimer on all results
- AI confidence displayed on every result

---

## License

MIT License — Built for IBM AI Competition 2025.
