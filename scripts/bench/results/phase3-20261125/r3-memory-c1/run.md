# End-to-end upload/download (http, memory providers)

Chunk size 1 MiB, replication as configured (R=2 of 3), 1 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T20:14:17+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 215 [215-215] | 23.2 [23.2-23.2] | 110 [110-110] | 45.3 [45.3-45.3] | 106 [106-106] | 108 | yes |
| 20 | 671 [671-671] | 29.8 [29.8-29.8] | 340 [340-340] | 58.8 [58.8-58.8] | 246 [246-246] | 131 | yes |
| 100 | 2857 [2857-2857] | 35.0 [35.0-35.0] | 1464 [1464-1464] | 68.3 [68.3-68.3] | 946 [946-946] | 206 | yes |
| 200 | 5130 [5130-5130] | 39.0 [39.0-39.0] | 2599 [2599-2599] | 77.0 [77.0-77.0] | 1714 [1714-1714] | 330 | yes |
| 1024 | 25453 [25453-25453] | 40.2 [40.2-40.2] | 14441 [14441-14441] | 70.9 [70.9-70.9] | 9106 [9106-9106] | 1131 | yes |
