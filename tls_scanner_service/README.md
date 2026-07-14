# TLS Scanner Service (Python)

This service provides a **live TLS + certificate telemetry** endpoint that the Node backend can call.

## Requirements
- Python 3.10+
- Install dependencies:
  ```bash
  pip install -r requirements.txt
  ```

## Run
```bash
python app.py --host 0.0.0.0 --port 8060
```

## API
### `POST /scan`
Body (JSON):
```json
{ "domain": "github.com" }
```

Response:
- `status: success|failed|parsing_error`
- `certificate_intel` includes parsed X.509 fields and embedded CT/SCT count (best-effort).


