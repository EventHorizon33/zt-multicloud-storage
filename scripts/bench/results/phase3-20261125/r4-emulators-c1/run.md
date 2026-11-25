# End-to-end upload/download (http, emulators providers)

Chunk size 1 MiB, replication as configured (R=2 of 3), 1 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T20:24:29+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 388 [388-388] | 12.9 [12.9-12.9] | 145 [145-145] | 34.5 [34.5-34.5] | 139 [139-139] | 151 | yes |
| 20 | 1542 [1542-1542] | 13.0 [13.0-13.0] | 593 [593-593] | 33.7 [33.7-33.7] | 504 [504-504] | 154 | yes |
| 100 | 7501 [7501-7501] | 13.3 [13.3-13.3] | 2448 [2448-2448] | 40.9 [40.9-40.9] | 1956 [1956-1956] | 166 | yes |
| 200 | 14860 [14860-14860] | 13.5 [13.5-13.5] | 4933 [4933-4933] | 40.5 [40.5-40.5] | 3864 [3864-3864] | 189 | yes |
| 1024 | 78565 [78565-78565] | 13.0 [13.0-13.0] | 26995 [26995-26995] | 37.9 [37.9-37.9] | 21122 [21122-21122] | 374 | yes |
