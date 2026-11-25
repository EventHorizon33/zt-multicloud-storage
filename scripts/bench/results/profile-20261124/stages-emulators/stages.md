# Stage timing: emulators providers, 100 MiB, chunk 1 MiB, 3 timed repeats (median)

Wrapped with wall-clock timers inside the benchmark server only (no application file changed). Timers add a little overhead of their own (a few microseconds per call). Exclusive = time in that function excluding timers nested inside it on the same thread. Request-thread exclusive times add up to the service call's wall time.


## Upload

- Client-measured wall time (whole HTTP request): **7261 ms**
- Time inside the service call (`SERVICE upload() total`): **7251 ms** (100% of wall); the other 10 ms is HTTP/framework work outside the service call (receiving or sending the body, routing, auth middleware, response)

**Request thread, by exclusive time** (the critical path):

| Stage | Calls | Exclusive ms | % of service call |
|---|---:|---:|---:|
| store_chunk (replicate to R providers) | 100 | 5740 | 79.2% |
| metadata DB commit (SQLite) | 207 | 492 | 6.8% |
| audit append (SQLite insert + commit) | 104 | 338 | 4.7% |
|   of which: multipart read() (waits on network) | 101 | 259 | 3.6% |
| encrypt_chunk (AES-256-GCM + SHA-256 of blob) | 100 | 169 | 2.3% |
| SHA-256 of plaintext (whole-file hash) | 100 | 107 | 1.5% |
| audit record() total | 104 | 79 | 1.1% |
| read body + split into chunks (iterator wait) | 101 | 3 | 0.0% |
| audit event raised by orchestrator | 100 | 1 | 0.0% |
| (everything else in the service call: queries, policy, bookkeeping) | | 62 | 0.9% |

**Other threads** (provider fan-out and deadline-runner pool; thread-seconds, run in parallel with the request thread):

| Thread kind | Operation | Calls | Inclusive ms (thread-s) | Mean ms/call |
|---|---|---:|---:|---:|
| io | provider put (GCSProvider) | 67 | 3495 | 52.16 |
| io | provider put (AzureBlobProvider) | 68 | 1753 | 25.78 |
| io | provider put (S3Provider) | 68 | 1093 | 16.08 |
| io | provider get (AzureBlobProvider) | 67 | 552 | 8.24 |
| io | provider get (S3Provider) | 67 | 512 | 7.64 |
| io | provider get (GCSProvider) | 66 | 297 | 4.49 |

## Download

- Client-measured wall time (whole HTTP request): **2292 ms**
- Time inside the service call (`SERVICE download() total`): **1804 ms** (79% of wall); the other 488 ms is HTTP/framework work outside the service call (receiving or sending the body, routing, auth middleware, response)

**Request thread, by exclusive time** (the critical path):

| Stage | Calls | Exclusive ms | % of service call |
|---|---:|---:|---:|
| fetch_chunk (get replica + verify SHA-256) | 100 | 1022 | 56.6% |
| audit append (SQLite insert + commit) | 103 | 325 | 18.0% |
| assemble (loop: fetch, decrypt, hash, spool) | 1 | 186 | 10.3% |
| decrypt_chunk (SHA-256 check + AES-256-GCM) | 100 | 168 | 9.3% |
| audit record() total | 103 | 78 | 4.3% |
| metadata DB commit (SQLite) | 6 | 11 | 0.6% |
| authorize (policy + DB read + audit) | 1 | 3 | 0.2% |
| open manifest + unwrap key (KMS) | 1 | 1 | 0.1% |
| audit event raised by orchestrator | 100 | 1 | 0.1% |
| (everything else in the service call: queries, policy, bookkeeping) | | 9 | 0.5% |

**Other threads** (provider fan-out and deadline-runner pool; thread-seconds, run in parallel with the request thread):

| Thread kind | Operation | Calls | Inclusive ms (thread-s) | Mean ms/call |
|---|---|---:|---:|---:|
| io | provider get (S3Provider) | 67 | 534 | 7.97 |
| io | provider get (AzureBlobProvider) | 33 | 357 | 10.82 |
| io | provider put (AzureBlobProvider) | 1 | 14 | 13.89 |
| io | provider put (S3Provider) | 1 | 12 | 11.54 |
| io | provider put (GCSProvider) | 1 | 9 | 9.02 |
