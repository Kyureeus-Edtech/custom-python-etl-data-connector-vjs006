# NVD CVE ETL Data Connector

This project is a Python ETL (Extract, Transform, Load) pipeline that fetches CVE (Common Vulnerabilities and Exposures) data from the [NVD Services API](https://nvd.nist.gov/developers/vulnerabilities) and ingests it into a MongoDB collection. It features robust error handling, secure environment variable management, and idempotent upserts using stable hashes.

---

## 📦 Files

```
etl_connector.py       # Main ETL logic (extract from NVD, transform, and load to MongoDB)
requirements.txt       # Python dependencies
.env                   # Environment variables (not committed; see ENV_TEMPLATE)
ENV_TEMPLATE           # Template for .env file
.gitignore             # Ensures .env and other junk are not committed
README.md              # Project documentation (you are here)
```

---

## 🚀 Quickstart

1. **Create and activate a virtual environment**
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate  # On Windows: .venv\Scripts\activate
    ```

2. **Install dependencies**
    ```bash
    pip install -r requirements.txt
    ```

3. **Configure environment variables**
    - Copy the template and fill in your values:
      ```bash
      cp ENV_TEMPLATE .env
      # Edit .env and set your MongoDB URI, DB, collection, and (optionally) NVD API key
      ```

4. **Run the ETL connector**
    ```bash
    python etl_connector.py
    ```

If configured correctly, the script will:
- Extract CVE data from the NVD API
- Transform it for MongoDB compatibility
- Insert documents into your MongoDB collection with an `ingested_at` timestamp

---

## 🔑 Environment Variables

Set these in your `.env` file:

| Variable              | Description                                 | Example/Default                      |
|-----------------------|---------------------------------------------|--------------------------------------|
| `MONGODB_URI`         | MongoDB connection string                   | `mongodb://localhost:27017`          |
| `MONGODB_DB`          | MongoDB database name                       | `etl_db`                             |
| `MONGODB_COLLECTION`  | MongoDB collection name                     | `nvd_cve_raw`                        |
| `API_BASE_URL`        | NVD API base URL                            | `https://services.nvd.nist.gov/rest/json/cves/2.0` |
| `API_KEY`             | (Optional) NVD API key for higher rate limits |                                      |
| `RESULTS_PER_PAGE`    | Number of results per API page              | `10`                                 |
| `START_INDEX`         | Pagination start index                      | `0`                                  |

---

## 🛠️ How It Works

- **Extraction:** Uses the NVD API to fetch CVE data with pagination and optional API key authentication.
- **Transformation:** Cleans and sanitizes records for MongoDB (removes dots from keys, handles `$` prefixes).
- **Loading:** Upserts each record into MongoDB using a stable hash (`hash_key`) for idempotency. Adds metadata such as `ingested_at` and `source`.

---

## 🧪 Validation & Error Handling

- Retries with exponential backoff for transient HTTP errors (using `tenacity`)
- Handles API rate limiting (HTTP 429) with respect to `Retry-After` headers
- Defensive checks for empty payloads and schema mismatches

---

## 🗃️ MongoDB Strategy

- One collection per connector (e.g., `nvd_cve_raw`)
- Each document includes:
  - `ingested_at` (UTC ISO string)
  - `source` (provider name)
  - `hash_key` (stable hash for idempotency/upserts)

---

## 🔗 NVD API Details

- **Base URL:** `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **Authentication:** Optional API key via `apiKey` header (get from [NVD API Key Registration](https://nvd.nist.gov/developers/request-an-api-key))
- **Endpoints Used:** `/cves/2.0`
- **Sample Request:**
    ```
    GET /rest/json/cves/2.0?resultsPerPage=10&startIndex=0
    Headers: { "apiKey": "<your-api-key>" }
    ```
- **Sample Response:**
    ```json
    {
      "resultsPerPage": 10,
      "startIndex": 0,
      "totalResults": 123456,
      "vulnerabilities": [
        {
          "cve": {
            "id": "CVE-2024-12345",
            "sourceIdentifier": "...",
            "published": "...",
            "lastModified": "...",
            "descriptions": [...],
            "metrics": {...},
            "weaknesses": [...],
            "configurations": [...],
            "references": [...]
          }
        },
        ...
      ]
    }
    ```

---