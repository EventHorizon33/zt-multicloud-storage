# End-to-end upload/download (http, emulators providers)

Chunk size 64 MiB, replication as configured (R=2 of 3), 3 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T12:27:02+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 107 [100-219] | 46.5 [22.8-49.9] | 49 [46-69] | 102.8 [72.7-109.6] | 43 [42-65] | 177 | yes |
| 20 | 303 [293-331] | 66.1 [60.5-68.3] | 157 [130-177] | 127.5 [112.8-153.9] | 116 [90-129] | 280 | yes |
| 100 | 1283 [1260-2081] | 77.9 [48.1-79.4] | 799 [767-824] | 125.1 [121.3-130.4] | 559 [541-565] | 428 | yes |
| 200 | 3909 [3879-3953] | 51.2 [50.6-51.6] | 1592 [1569-1638] | 125.6 [122.1-127.5] | 1081 [1081-1136] | 566 | yes |
