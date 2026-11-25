# End-to-end upload/download (http, memory providers)

Chunk size 1 MiB, replication as configured (R=2 of 3), 1 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T20:21:43+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 195 [195-195] | 25.6 [25.6-25.6] | 103 [103-103] | 48.8 [48.8-48.8] | 97 [97-97] | 109 | yes |
| 20 | 640 [640-640] | 31.2 [31.2-31.2] | 331 [331-331] | 60.5 [60.5-60.5] | 250 [250-250] | 126 | yes |
| 100 | 2938 [2938-2938] | 34.0 [34.0-34.0] | 1552 [1552-1552] | 64.5 [64.5-64.5] | 1020 [1020-1020] | 206 | yes |
| 200 | 5490 [5490-5490] | 36.4 [36.4-36.4] | 2913 [2913-2913] | 68.7 [68.7-68.7] | 1901 [1901-1901] | 321 | yes |
| 1024 | 26691 [26691-26691] | 38.4 [38.4-38.4] | 14615 [14615-14615] | 70.1 [70.1-70.1] | 8843 [8843-8843] | 1130 | yes |
