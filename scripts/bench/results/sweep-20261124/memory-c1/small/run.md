# End-to-end upload/download (http, memory providers)

Chunk size 1 MiB, replication as configured (R=2 of 3), 3 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T12:05:31+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 110 [76-129] | 45.3 [38.8-66.1] | 52 [47-73] | 96.5 [68.7-105.9] | 49 [44-70] | 107 | yes |
| 20 | 270 [269-303] | 74.1 [66.1-74.4] | 155 [144-156] | 129.0 [128.1-138.7] | 119 [109-120] | 131 | yes |
| 100 | 1326 [1296-1525] | 75.4 [65.6-77.2] | 658 [624-662] | 152.1 [151.0-160.3] | 431 [407-433] | 218 | yes |
| 200 | 2425 [2423-2451] | 82.5 [81.6-82.6] | 1214 [1193-1214] | 164.8 [164.7-167.6] | 772 [755-778] | 328 | yes |
