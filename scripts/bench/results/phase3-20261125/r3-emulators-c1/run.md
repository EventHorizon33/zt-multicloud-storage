# End-to-end upload/download (http, emulators providers)

Chunk size 1 MiB, replication as configured (R=2 of 3), 1 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T20:16:25+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 416 [416-416] | 12.0 [12.0-12.0] | 169 [169-169] | 29.6 [29.6-29.6] | 163 [163-163] | 144 | yes |
| 20 | 1545 [1545-1545] | 12.9 [12.9-12.9] | 539 [539-539] | 37.1 [37.1-37.1] | 437 [437-437] | 157 | yes |
| 100 | 7385 [7385-7385] | 13.5 [13.5-13.5] | 2441 [2441-2441] | 41.0 [41.0-41.0] | 1968 [1968-1968] | 169 | yes |
| 200 | 15147 [15147-15147] | 13.2 [13.2-13.2] | 5019 [5019-5019] | 39.8 [39.8-39.8] | 4014 [4014-4014] | 186 | yes |
| 1024 | 77707 [77707-77707] | 13.2 [13.2-13.2] | 27744 [27744-27744] | 36.9 [36.9-36.9] | 21428 [21428-21428] | 321 | yes |
