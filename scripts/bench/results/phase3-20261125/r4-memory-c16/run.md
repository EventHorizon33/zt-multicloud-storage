# End-to-end upload/download (http, memory providers)

Chunk size 16 MiB, replication as configured (R=2 of 3), 1 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T20:20:47+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 132 [132-132] | 37.9 [37.9-37.9] | 252 [252-252] | 19.9 [19.9-19.9] | 79 [79-79] | 107 | yes |
| 20 | 382 [382-382] | 52.4 [52.4-52.4] | 263 [263-263] | 76.2 [76.2-76.2] | 166 [166-166] | 151 | yes |
| 100 | 1449 [1449-1449] | 69.0 [69.0-69.0] | 1052 [1052-1052] | 95.1 [95.1-95.1] | 557 [557-557] | 252 | yes |
| 200 | 2962 [2962-2962] | 67.5 [67.5-67.5] | 2053 [2053-2053] | 97.4 [97.4-97.4] | 1124 [1124-1124] | 346 | yes |
| 1024 | 14527 [14527-14527] | 70.5 [70.5-70.5] | 11637 [11637-11637] | 88.0 [88.0-88.0] | 5313 [5313-5313] | 1179 | yes |
