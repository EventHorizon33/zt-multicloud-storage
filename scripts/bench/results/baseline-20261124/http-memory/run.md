# End-to-end upload/download (http, memory providers)

Chunk size 1 MiB, replication as configured (R=2 of 3), 5 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T10:19:59+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 178 [154-233] | 28.2 [21.5-32.5] | 107 [94-125] | 46.6 [40.0-53.5] | 103 [88-120] | 108 | yes |
| 20 | 579 [559-997] | 34.5 [20.1-35.8] | 332 [325-363] | 60.2 [55.1-61.5] | 244 [240-260] | 130 | yes |
| 100 | 2780 [2623-2940] | 36.0 [34.0-38.1] | 1451 [1424-1496] | 68.9 [66.9-70.2] | 928 [872-975] | 221 | yes |
| 200 | 4974 [4857-5288] | 40.2 [37.8-41.2] | 2677 [2429-2885] | 74.7 [69.3-82.3] | 1714 [1540-1791] | 307 | yes |
