# End-to-end upload/download (http, emulators providers)

Chunk size 32 MiB, replication as configured (R=2 of 3), 3 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T12:24:06+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 182 [105-187] | 27.5 [26.8-47.6] | 59 [47-60] | 84.6 [83.5-105.5] | 44 [39-54] | 177 | yes |
| 20 | 274 [270-286] | 73.0 [69.8-74.1] | 157 [130-163] | 127.6 [122.4-154.3] | 120 [94-123] | 272 | yes |
| 100 | 1304 [1248-1353] | 76.7 [73.9-80.1] | 747 [738-750] | 133.9 [133.3-135.5] | 535 [526-536] | 391 | yes |
| 200 | 2450 [2432-2509] | 81.6 [79.7-82.2] | 1517 [1380-1578] | 131.9 [126.7-144.9] | 1045 [930-1074] | 410 | yes |
