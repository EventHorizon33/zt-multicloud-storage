# End-to-end upload/download (http, emulators providers)

Chunk size 1 MiB, replication as configured (R=2 of 3), 1 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T20:11:24+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 481 [481-481] | 10.4 [10.4-10.4] | 188 [188-188] | 26.7 [26.7-26.7] | 180 [180-180] | 154 | yes |
| 20 | 1595 [1595-1595] | 12.5 [12.5-12.5] | 569 [569-569] | 35.1 [35.1-35.1] | 483 [483-483] | 157 | yes |
| 100 | 7688 [7688-7688] | 13.0 [13.0-13.0] | 2504 [2504-2504] | 39.9 [39.9-39.9] | 2035 [2035-2035] | 163 | yes |
| 200 | 14916 [14916-14916] | 13.4 [13.4-13.4] | 5152 [5152-5152] | 38.8 [38.8-38.8] | 4193 [4193-4193] | 198 | yes |
| 1024 | 77756 [77756-77756] | 13.2 [13.2-13.2] | 26227 [26227-26227] | 39.0 [39.0-39.0] | 20585 [20585-20585] | 328 | yes |
