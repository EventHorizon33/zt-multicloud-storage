# End-to-end upload/download (http, emulators providers)

Chunk size 16 MiB, replication as configured (R=2 of 3), 1 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T20:32:25+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 216 [216-216] | 23.1 [23.1-23.1] | 84 [84-84] | 59.5 [59.5-59.5] | 78 [78-78] | 169 | yes |
| 20 | 916 [916-916] | 21.8 [21.8-21.8] | 287 [287-287] | 69.8 [69.8-69.8] | 199 [199-199] | 241 | yes |
| 100 | 1638 [1638-1638] | 61.1 [61.1-61.1] | 829 [829-829] | 120.6 [120.6-120.6] | 498 [498-498] | 321 | yes |
| 200 | 5015 [5015-5015] | 39.9 [39.9-39.9] | 2863 [2863-2863] | 69.9 [69.9-69.9] | 1891 [1891-1891] | 306 | yes |
| 1024 | 24356 [24356-24356] | 42.0 [42.0-42.0] | 14398 [14398-14398] | 71.1 [71.1-71.1] | 8436 [8436-8436] | 373 | yes |
