# End-to-end upload/download (http, emulators providers)

Chunk size 4 MiB, replication as configured (R=2 of 3), 3 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T12:15:04+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 175 [162-249] | 28.6 [20.1-30.8] | 69 [62-72] | 72.0 [69.1-81.0] | 67 [58-68] | 167 | yes |
| 20 | 649 [644-703] | 30.8 [28.4-31.1] | 199 [196-207] | 100.6 [96.5-101.8] | 153 [151-154] | 187 | yes |
| 100 | 3035 [3007-3115] | 33.0 [32.1-33.3] | 834 [814-845] | 119.9 [118.3-122.9] | 570 [562-590] | 194 | yes |
| 200 | 5944 [5689-5973] | 33.6 [33.5-35.2] | 1642 [1523-1659] | 121.8 [120.6-131.3] | 1091 [1039-1141] | 198 | yes |
