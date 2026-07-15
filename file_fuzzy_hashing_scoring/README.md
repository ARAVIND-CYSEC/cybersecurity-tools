TODO: Implement fuzzy hashing + behavior scoring pipeline.

Planned endpoint: POST /api/file/analysis
Input: multipart/form-data with file
Outputs:
- sha1/sha256
- ssdeep/tlsh fuzzy hashes
- entropy + magic byte + strings indicators
- optional detonation for URL payloads (if file is URL/macro) - later
- final similarity graph across prior artifacts (later)

Implementation approach (Phase 1):
1) Backend service in Python/FastAPI or extend existing microservices.
2) Add fuzzy hash computation.
3) Add scoring heuristics.
4) Wire UI (tools-lab.html hashing subtab) to call backend.

