# End-to-end upload/download (http, emulators providers)

Chunk size 8 MiB, replication as configured (R=2 of 3), 3 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T12:18:44+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 183 [107-188] | 27.3 [26.6-46.9] | 47 [41-52] | 105.8 [97.0-121.1] | 44 [39-48] | 173 | yes |
| 20 | 378 [300-407] | 52.9 [49.2-66.7] | 165 [154-176] | 121.5 [113.9-129.5] | 129 [120-131] | 218 | yes |
| 100 | 1293 [1253-1328] | 77.3 [75.3-79.8] | 735 [692-738] | 136.0 [135.5-144.5] | 518 [482-525] | 243 | yes |
| 200 | 2404 [2360-2432] | 83.2 [82.2-84.8] | 1417 [1391-1502] | 141.1 [133.2-143.8] | 966 [945-1038] | 242 | yes |
