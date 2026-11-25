# End-to-end upload/download (http, emulators providers)

Chunk size 16 MiB, replication as configured (R=2 of 3), 1 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T20:19:19+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 195 [195-195] | 25.6 [25.6-25.6] | 99 [99-99] | 50.6 [50.6-50.6] | 93 [93-93] | 163 | yes |
| 20 | 907 [907-907] | 22.0 [22.0-22.0] | 310 [310-310] | 64.4 [64.4-64.4] | 230 [230-230] | 239 | yes |
| 100 | 2488 [2488-2488] | 40.2 [40.2-40.2] | 1381 [1381-1381] | 72.4 [72.4-72.4] | 904 [904-904] | 302 | yes |
| 200 | 4874 [4874-4874] | 41.0 [41.0-41.0] | 2964 [2964-2964] | 67.5 [67.5-67.5] | 1955 [1955-1955] | 306 | yes |
| 1024 | 23588 [23588-23588] | 43.4 [43.4-43.4] | 16666 [16666-16666] | 61.4 [61.4-61.4] | 9974 [9974-9974] | 371 | yes |
