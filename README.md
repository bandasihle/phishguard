# PhishGuard

Phishing URL detector — React frontend + Python/Flask ML backend.

**97.1% accuracy** on the UCI phishing dataset (11,055 URLs, Random Forest, 200 trees).

## Project structure

```
phishguard/
├── backend/
│   ├── feature_extractor.py   # URL feature engineering (30 features)
│   ├── train_model.py         # Model training script
│   ├── app.py                 # Flask API server
│   └── requirements.txt
├── src/
│   ├── App.tsx                # Main UI component
│   ├── services/api.ts        # API client
│   └── components/ui/         # shadcn/ui components
├── index.html
├── vite.config.ts
└── package.json
```

## Setup

### Backend

```bash
cd backend
pip install -r requirements.txt

# Train the model (requires Training Dataset.arff in the parent folder)
python train_model.py

# Start the API server
python app.py
# → http://localhost:5000
```

**Training data:** Download the UCI Phishing Websites dataset (ARFF format) and place it at `Training Dataset.arff` one level above the backend folder, or pass the path directly:

```bash
python train_model.py path/to/dataset.arff
# or with a CSV (columns: url, label)
python train_model.py path/to/urls.csv
```

### Frontend

```bash
npm install
npm run dev
# → http://localhost:5173
```

Requires the backend to be running on port 5000.

## API endpoints

| Method | Path | Body | Description |
|--------|------|------|-------------|
| GET | `/health` | — | Model status and accuracy |
| POST | `/analyze` | `{ "url": "..." }` | Analyze a single URL |
| POST | `/bulk` | `{ "urls": ["..."] }` | Analyze up to 50 URLs |

### Example

```bash
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "http://paypal-secure.ru/login"}'
```

## How it works

Features are extracted from the URL structure alone (IP detection, HTTPS, subdomain depth, shorteners, special characters, port, etc.) and fed into a Random Forest classifier trained on the UCI dataset. 14 of 30 features require page fetching or WHOIS lookups — these default to neutral when not available, which is reflected in confidence scores on borderline URLs.
