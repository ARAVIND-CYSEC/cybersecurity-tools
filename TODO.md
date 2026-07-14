- [ ] Add robust parseUserDomainInput() to server.js
- [x] Update /api/security/ssl to use parsed hostname (not raw query)

- [x] Ensure normalization strips protocol, path, query, www., and optional :port

- [x] Validate hostname safely with existing isLikelyDomain()

- [ ] Quick smoke-test by running server and calling /api/security/ssl with multiple input formats


