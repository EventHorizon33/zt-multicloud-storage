# Stage timing: emulators providers, 100 MiB, chunk 8 MiB, 3 timed repeats (median)

Wrapped with wall-clock timers inside the benchmark server only (no application file changed). Timers add a little overhead of their own (a few microseconds per call). Exclusive = time in that function excluding timers nested inside it on the same thread. Request-thread exclusive times add up to the service call's wall time.


## Upload

- Client-measured wall time (whole HTTP request): **2758 ms**
- Time inside the service call (`SERVICE upload() total`): **2743 ms** (99% of wall); the other 15 ms is HTTP/framework work outside the service call (receiving or sending the body, routing, auth middleware, response)

**Request thread, by exclusive time** (the critical path):

| Stage | Calls | Exclusive ms | % of service call |
|---|---:|---:|---:|
| store_chunk (replicate to R providers) | 13 | 1962 | 71.5% |
|   of which: multipart read() (waits on network) | 14 | 216 | 7.9% |
| encrypt_chunk (AES-256-GCM + SHA-256 of blob) | 13 | 187 | 6.8% |
| metadata DB commit (SQLite) | 33 | 157 | 5.7% |
| SHA-256 of plaintext (whole-file hash) | 13 | 106 | 3.9% |
| audit append (SQLite insert + commit) | 17 | 104 | 3.8% |
| audit record() total | 17 | 11 | 0.4% |
| read body + split into chunks (iterator wait) | 14 | 1 | 0.0% |
| audit event raised by orchestrator | 13 | 0 | 0.0% |
| (everything else in the service call: queries, policy, bookkeeping) | | -2 | -0.1% |

**Other threads** (provider fan-out and deadline-runner pool; thread-seconds, run in parallel with the request thread):

| Thread kind | Operation | Calls | Inclusive ms (thread-s) | Mean ms/call |
|---|---|---:|---:|---:|
| io | provider put (AzureBlobProvider) | 9 | 821 | 91.21 |
| io | provider put (GCSProvider) | 9 | 589 | 65.44 |
| io | provider put (S3Provider) | 9 | 568 | 63.06 |
| io | provider get (AzureBlobProvider) | 9 | 351 | 39.05 |
| io | provider get (GCSProvider) | 9 | 195 | 21.66 |
| io | provider get (S3Provider) | 9 | 147 | 16.37 |

## Download

- Client-measured wall time (whole HTTP request): **1578 ms**
- Time inside the service call (`SERVICE download() total`): **1043 ms** (66% of wall); the other 535 ms is HTTP/framework work outside the service call (receiving or sending the body, routing, auth middleware, response)

**Request thread, by exclusive time** (the critical path):

| Stage | Calls | Exclusive ms | % of service call |
|---|---:|---:|---:|
| fetch_chunk (get replica + verify SHA-256) | 13 | 540 | 51.8% |
| assemble (loop: fetch, decrypt, hash, spool) | 1 | 189 | 18.1% |
| decrypt_chunk (SHA-256 check + AES-256-GCM) | 13 | 189 | 18.1% |
| audit append (SQLite insert + commit) | 16 | 84 | 8.1% |
| metadata DB commit (SQLite) | 6 | 25 | 2.4% |
| audit record() total | 16 | 11 | 1.1% |
| authorize (policy + DB read + audit) | 1 | 4 | 0.4% |
| audit event raised by orchestrator | 13 | 0 | 0.0% |
| (everything else in the service call: queries, policy, bookkeeping) | | 1 | 0.1% |

**Other threads** (provider fan-out and deadline-runner pool; thread-seconds, run in parallel with the request thread):

| Thread kind | Operation | Calls | Inclusive ms (thread-s) | Mean ms/call |
|---|---|---:|---:|---:|
| io | provider get (AzureBlobProvider) | 4 | 245 | 61.22 |
| io | provider get (S3Provider) | 9 | 213 | 23.69 |
| io | provider put (AzureBlobProvider) | 0 | 0 | 0.00 |
| io | provider put (GCSProvider) | 0 | 0 | 0.00 |
| io | provider put (S3Provider) | 0 | 0 | 0.00 |
