# Stage timing: memory providers, 100 MiB, chunk 8 MiB, 3 timed repeats (median)

Wrapped with wall-clock timers inside the benchmark server only (no application file changed). Timers add a little overhead of their own (a few microseconds per call). Exclusive = time in that function excluding timers nested inside it on the same thread. Request-thread exclusive times add up to the service call's wall time.


## Upload

- Client-measured wall time (whole HTTP request): **1500 ms**
- Time inside the service call (`SERVICE upload() total`): **1484 ms** (99% of wall); the other 16 ms is HTTP/framework work outside the service call (receiving or sending the body, routing, auth middleware, response)

**Request thread, by exclusive time** (the critical path):

| Stage | Calls | Exclusive ms | % of service call |
|---|---:|---:|---:|
| store_chunk (replicate to R providers) | 13 | 684 | 46.1% |
|   of which: multipart read() (waits on network) | 14 | 250 | 16.9% |
| encrypt_chunk (AES-256-GCM + SHA-256 of blob) | 13 | 195 | 13.1% |
| metadata DB commit (SQLite) | 33 | 155 | 10.4% |
| SHA-256 of plaintext (whole-file hash) | 13 | 97 | 6.5% |
| audit append (SQLite insert + commit) | 17 | 93 | 6.3% |
| audit record() total | 17 | 10 | 0.7% |
| read body + split into chunks (iterator wait) | 14 | 1 | 0.1% |
| audit event raised by orchestrator | 13 | 0 | 0.0% |
| (everything else in the service call: queries, policy, bookkeeping) | | -1 | -0.1% |

**Other threads** (provider fan-out and deadline-runner pool; thread-seconds, run in parallel with the request thread):

| Thread kind | Operation | Calls | Inclusive ms (thread-s) | Mean ms/call |
|---|---|---:|---:|---:|
| io | provider put (MemoryProvider) | 26 | 471 | 18.10 |
| io | provider get (MemoryProvider) | 26 | 0 | 0.02 |

## Download

- Client-measured wall time (whole HTTP request): **1131 ms**
- Time inside the service call (`SERVICE download() total`): **609 ms** (54% of wall); the other 523 ms is HTTP/framework work outside the service call (receiving or sending the body, routing, auth middleware, response)

**Request thread, by exclusive time** (the critical path):

| Stage | Calls | Exclusive ms | % of service call |
|---|---:|---:|---:|
| assemble (loop: fetch, decrypt, hash, spool) | 1 | 198 | 32.5% |
| decrypt_chunk (SHA-256 check + AES-256-GCM) | 13 | 185 | 30.3% |
| fetch_chunk (get replica + verify SHA-256) | 13 | 115 | 18.9% |
| audit append (SQLite insert + commit) | 16 | 84 | 13.7% |
| metadata DB commit (SQLite) | 6 | 19 | 3.2% |
| audit record() total | 16 | 11 | 1.7% |
| authorize (policy + DB read + audit) | 1 | 4 | 0.7% |
| audit event raised by orchestrator | 13 | 0 | 0.0% |
| (everything else in the service call: queries, policy, bookkeeping) | | -7 | -1.2% |

**Other threads** (provider fan-out and deadline-runner pool; thread-seconds, run in parallel with the request thread):

| Thread kind | Operation | Calls | Inclusive ms (thread-s) | Mean ms/call |
|---|---|---:|---:|---:|
| io | provider get (MemoryProvider) | 13 | 0 | 0.02 |
| io | provider put (MemoryProvider) | 0 | 0 | 0.00 |
