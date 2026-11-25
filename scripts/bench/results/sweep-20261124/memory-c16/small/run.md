# End-to-end upload/download (http, memory providers)

Chunk size 16 MiB, replication as configured (R=2 of 3), 3 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T12:20:27+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 62 [59-65] | 80.3 [77.2-84.2] | 40 [35-41] | 125.3 [122.7-144.7] | 37 [32-37] | 107 | yes |
| 20 | 175 [166-199] | 114.2 [100.6-120.2] | 124 [124-146] | 160.7 [136.7-160.9] | 87 [82-88] | 166 | yes |
| 100 | 734 [706-778] | 136.2 [128.6-141.6] | 524 [483-531] | 190.9 [188.3-207.2] | 278 [268-287] | 282 | yes |
| 200 | 1377 [1374-1380] | 145.2 [145.0-145.5] | 998 [983-1002] | 200.4 [199.5-203.5] | 498 [494-555] | 378 | yes |
