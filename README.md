# Custom Python ETL Data Connector — Template

This folder is a **starter template** for the SSN CSE × Kyureeus *Software Architecture* assignment.
It demonstrates a clean, testable ETL structure with secure env handling, pagination, retries, and MongoDB inserts with ingestion timestamps.

> Replace the example provider with your chosen API and update the README accordingly.

---

## 📦 Files

```
etl_connector.py       # Main ETL with BaseConnector + example provider implementation
requirements.txt       # Python dependencies
.env.example           # Sample environment variables (copy to .env and fill)
.gitignore             # Ensures .env and other junk are not committed
README.md              # You are here
```

---

## 🚀 Quickstart

1) **Create and activate a virtual env**
```bash
python3 -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
```

2) **Install dependencies**
```bash
pip install -r requirements.txt
```

3) **Create your `.env`**
```bash
cp .env.example .env
# Open `.env` and fill in real values (API keys, DB URI, etc.)
```

4) **Run the connector**
```bash
python etl_connector.py
```

If everything is configured correctly, the script will:
- Extract data from your API
- Transform it for MongoDB safety
- Write documents into the configured collection with an `ingested_at` timestamp

---

## 🧪 Validation & Error Handling

- Retries with exponential backoff for transient HTTP errors
- Pagination helpers
- Rate-limit friendly sleeps
- Input validation with Pydantic models
- Defensive checks for empty payloads and schema mismatches

---

## 🗃️ MongoDB Strategy

- One collection per connector (e.g., `connectorname_raw`)
- Each document receives:
  - `ingested_at` (UTC ISO string)
  - `source` (provider name)
  - `hash_key` (stable hash for idempotency/upserts)

---

## ✍️ Submission Notes

- **Commit messages must include your Name and Roll Number**
  - Example: `feat: add weather ETL — Vijay Srinivas K (20XXCSXXX)`
- Do **not** commit `.env`.
- Update this README with your **API details**, authentication method, endpoints, sample request/response, and **how to run**.

Happy coding! 🚀
