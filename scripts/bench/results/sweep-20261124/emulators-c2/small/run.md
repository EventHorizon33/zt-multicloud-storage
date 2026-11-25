# End-to-end upload/download (http, emulators providers)

Chunk size 2 MiB, replication as configured (R=2 of 3), 3 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T12:11:10+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 190 [175-254] | 26.4 [19.7-28.6] | 70 [63-81] | 71.6 [62.1-79.3] | 67 [60-76] | 154 | yes |
| 20 | 634 [619-665] | 31.5 [30.1-32.3] | 199 [199-205] | 100.4 [97.8-100.7] | 161 [158-166] | 164 | yes |
| 100 | 3055 [3016-3082] | 32.7 [32.4-33.2] | 932 [888-940] | 107.3 [106.3-112.6] | 700 [670-712] | 175 | yes |
| 200 | 6059 [6043-6140] | 33.0 [32.6-33.1] | 1739 [1723-1814] | 115.0 [110.3-116.1] | 1296 [1274-1318] | 176 | yes |
