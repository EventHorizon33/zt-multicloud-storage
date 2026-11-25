# End-to-end upload/download (http, memory providers)

Chunk size 2 MiB, replication as configured (R=2 of 3), 3 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T12:10:01+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 75 [71-75] | 67.1 [66.8-70.1] | 44 [44-47] | 113.3 [106.0-114.9] | 42 [40-44] | 110 | yes |
| 20 | 227 [216-235] | 88.2 [85.0-92.6] | 137 [137-153] | 145.6 [130.5-145.8] | 96 [92-104] | 135 | yes |
| 100 | 1031 [994-1142] | 97.0 [87.6-100.6] | 683 [602-694] | 146.5 [144.1-166.0] | 417 [359-455] | 223 | yes |
| 200 | 1965 [1929-1986] | 101.8 [100.7-103.7] | 1081 [1069-1171] | 185.1 [170.8-187.1] | 621 [610-686] | 312 | yes |
