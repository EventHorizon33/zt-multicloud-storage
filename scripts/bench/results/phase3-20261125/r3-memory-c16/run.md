# End-to-end upload/download (http, memory providers)

Chunk size 16 MiB, replication as configured (R=2 of 3), 1 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T20:15:31+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 118 [118-118] | 42.5 [42.5-42.5] | 77 [77-77] | 64.7 [64.7-64.7] | 71 [71-71] | 106 | yes |
| 20 | 351 [351-351] | 57.0 [57.0-57.0] | 253 [253-253] | 78.9 [78.9-78.9] | 169 [169-169] | 151 | yes |
| 100 | 1387 [1387-1387] | 72.1 [72.1-72.1] | 1038 [1038-1038] | 96.3 [96.3-96.3] | 539 [539-539] | 248 | yes |
| 200 | 2961 [2961-2961] | 67.5 [67.5-67.5] | 2055 [2055-2055] | 97.3 [97.3-97.3] | 1094 [1094-1094] | 346 | yes |
| 1024 | 14366 [14366-14366] | 71.3 [71.3-71.3] | 10474 [10474-10474] | 97.8 [97.8-97.8] | 5272 [5272-5272] | 1168 | yes |
