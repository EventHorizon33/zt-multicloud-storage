# End-to-end upload/download (http, emulators providers)

Chunk size 16 MiB, replication as configured (R=2 of 3), 3 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T12:21:26+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 108 [102-191] | 46.2 [26.1-48.8] | 47 [43-47] | 106.8 [105.8-117.6] | 43 [39-44] | 172 | yes |
| 20 | 371 [271-382] | 53.9 [52.3-73.8] | 150 [142-155] | 133.4 [129.0-140.8] | 113 [103-117] | 240 | yes |
| 100 | 1100 [1089-1122] | 90.9 [89.1-91.8] | 637 [618-693] | 157.0 [144.4-161.7] | 420 [406-475] | 309 | yes |
| 200 | 2139 [2084-2144] | 93.5 [93.3-95.9] | 1266 [1232-1319] | 158.0 [151.6-162.4] | 803 [802-855] | 354 | yes |
