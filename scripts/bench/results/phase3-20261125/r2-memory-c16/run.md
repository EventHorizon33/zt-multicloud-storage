# End-to-end upload/download (http, memory providers)

Chunk size 16 MiB, replication as configured (R=2 of 3), 1 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T20:07:53+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 131 [131-131] | 38.3 [38.3-38.3] | 86 [86-86] | 58.0 [58.0-58.0] | 76 [76-76] | 107 | yes |
| 20 | 374 [374-374] | 53.4 [53.4-53.4] | 237 [237-237] | 84.4 [84.4-84.4] | 144 [144-144] | 150 | yes |
| 100 | 1396 [1396-1396] | 71.6 [71.6-71.6] | 1171 [1171-1171] | 85.4 [85.4-85.4] | 556 [556-556] | 248 | yes |
| 200 | 2762 [2762-2762] | 72.4 [72.4-72.4] | 2102 [2102-2102] | 95.2 [95.2-95.2] | 1028 [1028-1028] | 346 | yes |
| 1024 | 13403 [13403-13403] | 76.4 [76.4-76.4] | 11289 [11289-11289] | 90.7 [90.7-90.7] | 5322 [5322-5322] | 1194 | yes |
