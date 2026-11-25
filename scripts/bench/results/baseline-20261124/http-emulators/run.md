# End-to-end upload/download (http, emulators providers)

Chunk size 1 MiB, replication as configured (R=2 of 3), 5 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T10:25:30+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 421 [388-433] | 11.9 [11.6-12.9] | 156 [143-163] | 32.0 [30.7-35.1] | 149 [136-158] | 151 | yes |
| 20 | 1595 [1551-1654] | 12.5 [12.1-12.9] | 546 [481-581] | 36.6 [34.4-41.6] | 461 [404-497] | 160 | yes |
| 100 | 7466 [7318-7733] | 13.4 [12.9-13.7] | 2426 [2359-2442] | 41.2 [40.9-42.4] | 1896 [1881-1973] | 178 | yes |
| 200 | 14571 [14363-14663] | 13.7 [13.6-13.9] | 4588 [4463-4641] | 43.6 [43.1-44.8] | 3600 [3509-3746] | 187 | yes |
