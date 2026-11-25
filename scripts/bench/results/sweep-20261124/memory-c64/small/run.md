# End-to-end upload/download (http, memory providers)

Chunk size 64 MiB, replication as configured (R=2 of 3), 3 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T12:25:55+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 76 [72-89] | 65.9 [56.1-69.8] | 47 [40-55] | 105.8 [91.4-123.9] | 43 [38-51] | 107 | yes |
| 20 | 219 [189-260] | 91.1 [77.0-105.6] | 144 [142-147] | 138.4 [135.8-140.5] | 100 [96-107] | 152 | yes |
| 100 | 799 [786-823] | 125.2 [121.5-127.3] | 619 [573-669] | 161.5 [149.4-174.6] | 351 [349-446] | 328 | yes |
| 200 | 1587 [1570-1593] | 126.0 [125.6-127.4] | 1209 [1165-1240] | 165.5 [161.3-171.6] | 702 [656-719] | 490 | yes |
