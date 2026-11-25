# End-to-end upload/download (http, memory providers)

Chunk size 16 MiB, replication as configured (R=2 of 3), 1 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T20:02:41+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 142 [142-142] | 35.3 [35.3-35.3] | 85 [85-85] | 59.2 [59.2-59.2] | 77 [77-77] | 107 | yes |
| 20 | 452 [452-452] | 44.2 [44.2-44.2] | 283 [283-283] | 70.7 [70.7-70.7] | 194 [194-194] | 151 | yes |
| 100 | 1480 [1480-1480] | 67.6 [67.6-67.6] | 1062 [1062-1062] | 94.2 [94.2-94.2] | 596 [596-596] | 247 | yes |
| 200 | 2959 [2959-2959] | 67.6 [67.6-67.6] | 2026 [2026-2026] | 98.7 [98.7-98.7] | 1068 [1068-1068] | 363 | yes |
| 1024 | 14421 [14421-14421] | 71.0 [71.0-71.0] | 11722 [11722-11722] | 87.4 [87.4-87.4] | 5614 [5614-5614] | 1196 | yes |
