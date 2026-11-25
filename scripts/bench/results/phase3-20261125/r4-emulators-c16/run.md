# End-to-end upload/download (http, emulators providers)

Chunk size 16 MiB, replication as configured (R=2 of 3), 1 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T20:23:01+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 414 [414-414] | 12.1 [12.1-12.1] | 109 [109-109] | 45.8 [45.8-45.8] | 102 [102-102] | 166 | yes |
| 20 | 604 [604-604] | 33.1 [33.1-33.1] | 311 [311-311] | 64.4 [64.4-64.4] | 218 [218-218] | 235 | yes |
| 100 | 2603 [2603-2603] | 38.4 [38.4-38.4] | 1413 [1413-1413] | 70.8 [70.8-70.8] | 957 [957-957] | 325 | yes |
| 200 | 4691 [4691-4691] | 42.6 [42.6-42.6] | 2832 [2832-2832] | 70.6 [70.6-70.6] | 1805 [1805-1805] | 321 | yes |
| 1024 | 23501 [23501-23501] | 43.6 [43.6-43.6] | 15861 [15861-15861] | 64.6 [64.6-64.6] | 10177 [10177-10177] | 351 | yes |
