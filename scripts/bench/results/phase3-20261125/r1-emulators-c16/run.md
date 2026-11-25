# End-to-end upload/download (http, emulators providers)

Chunk size 16 MiB, replication as configured (R=2 of 3), 1 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T20:06:25+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 563 [563-563] | 8.9 [8.9-8.9] | 120 [120-120] | 41.8 [41.8-41.8] | 114 [114-114] | 176 | yes |
| 20 | 991 [991-991] | 20.2 [20.2-20.2] | 332 [332-332] | 60.2 [60.2-60.2] | 251 [251-251] | 239 | yes |
| 100 | 2324 [2324-2324] | 43.0 [43.0-43.0] | 1490 [1490-1490] | 67.1 [67.1-67.1] | 962 [962-962] | 309 | yes |
| 200 | 5043 [5043-5043] | 39.7 [39.7-39.7] | 2859 [2859-2859] | 69.9 [69.9-69.9] | 1817 [1817-1817] | 323 | yes |
| 1024 | 23207 [23207-23207] | 44.1 [44.1-44.1] | 15736 [15736-15736] | 65.1 [65.1-65.1] | 10015 [10015-10015] | 354 | yes |
