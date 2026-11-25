# Stage timing: memory providers, 100 MiB, chunk 1 MiB, 3 timed repeats (median)

Wrapped with wall-clock timers inside the benchmark server only (no application file changed). Timers add a little overhead of their own (a few microseconds per call). Exclusive = time in that function excluding timers nested inside it on the same thread. Request-thread exclusive times add up to the service call's wall time.


## Upload

- Client-measured wall time (whole HTTP request): **2397 ms**
- Time inside the service call (`SERVICE upload() total`): **2386 ms** (100% of wall); the other 11 ms is HTTP/framework work outside the service call (receiving or sending the body, routing, auth middleware, response)

**Request thread, by exclusive time** (the critical path):

| Stage | Calls | Exclusive ms | % of service call |
|---|---:|---:|---:|
| store_chunk (replicate to R providers) | 100 | 873 | 36.6% |
| metadata DB commit (SQLite) | 207 | 501 | 21.0% |
|   of which: multipart read() (waits on network) | 101 | 357 | 15.0% |
| audit append (SQLite insert + commit) | 104 | 320 | 13.4% |
| encrypt_chunk (AES-256-GCM + SHA-256 of blob) | 100 | 169 | 7.1% |
| SHA-256 of plaintext (whole-file hash) | 100 | 98 | 4.1% |
| audit record() total | 104 | 61 | 2.6% |
| read body + split into chunks (iterator wait) | 101 | 3 | 0.1% |
| audit event raised by orchestrator | 100 | 1 | 0.1% |
| (everything else in the service call: queries, policy, bookkeeping) | | 2 | 0.1% |

**Other threads** (provider fan-out and deadline-runner pool; thread-seconds, run in parallel with the request thread):

| Thread kind | Operation | Calls | Inclusive ms (thread-s) | Mean ms/call |
|---|---|---:|---:|---:|
| io | provider put (MemoryProvider) | 203 | 493 | 2.43 |
| io | provider get (MemoryProvider) | 200 | 2 | 0.01 |

## Download

- Client-measured wall time (whole HTTP request): **1363 ms**
- Time inside the service call (`SERVICE download() total`): **874 ms** (64% of wall); the other 488 ms is HTTP/framework work outside the service call (receiving or sending the body, routing, auth middleware, response)

**Request thread, by exclusive time** (the critical path):

| Stage | Calls | Exclusive ms | % of service call |
|---|---:|---:|---:|
| audit append (SQLite insert + commit) | 103 | 309 | 35.4% |
| assemble (loop: fetch, decrypt, hash, spool) | 1 | 199 | 22.8% |
| decrypt_chunk (SHA-256 check + AES-256-GCM) | 100 | 159 | 18.2% |
| fetch_chunk (get replica + verify SHA-256) | 100 | 152 | 17.4% |
| audit record() total | 103 | 53 | 6.0% |
| metadata DB commit (SQLite) | 6 | 9 | 1.0% |
| authorize (policy + DB read + audit) | 1 | 3 | 0.4% |
| open manifest + unwrap key (KMS) | 1 | 2 | 0.2% |
| audit event raised by orchestrator | 100 | 1 | 0.1% |
| (everything else in the service call: queries, policy, bookkeeping) | | -13 | -1.5% |

**Other threads** (provider fan-out and deadline-runner pool; thread-seconds, run in parallel with the request thread):

| Thread kind | Operation | Calls | Inclusive ms (thread-s) | Mean ms/call |
|---|---|---:|---:|---:|
| io | provider get (MemoryProvider) | 100 | 2 | 0.02 |
| io | provider put (MemoryProvider) | 3 | 0 | 0.03 |
