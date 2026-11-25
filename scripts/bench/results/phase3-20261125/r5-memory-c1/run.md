# End-to-end upload/download (http, memory providers)

Chunk size 1 MiB, replication as configured (R=2 of 3), 1 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T20:27:23+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 450 [450-450] | 11.1 [11.1-11.1] | 124 [124-124] | 40.4 [40.4-40.4] | 118 [118-118] | 105 | yes |
| 20 | 671 [671-671] | 29.8 [29.8-29.8] | 384 [384-384] | 52.0 [52.0-52.0] | 302 [302-302] | 126 | yes |
| 100 | 2783 [2783-2783] | 35.9 [35.9-35.9] | 1396 [1396-1396] | 71.6 [71.6-71.6] | 899 [899-899] | 206 | yes |
| 200 | 5340 [5340-5340] | 37.4 [37.4-37.4] | 2977 [2977-2977] | 67.2 [67.2-67.2] | 1954 [1954-1954] | 306 | yes |
| 1024 | 27021 [27021-27021] | 37.9 [37.9-37.9] | 14361 [14361-14361] | 71.3 [71.3-71.3] | 8785 [8785-8785] | 1131 | yes |
