# End-to-end upload/download (http, emulators providers)

Chunk size 16 MiB, replication as configured (R=2 of 3), 1 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T20:10:02+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 232 [232-232] | 21.6 [21.6-21.6] | 101 [101-101] | 49.6 [49.6-49.6] | 93 [93-93] | 164 | yes |
| 20 | 836 [836-836] | 23.9 [23.9-23.9] | 371 [371-371] | 53.9 [53.9-53.9] | 288 [288-288] | 256 | yes |
| 100 | 2529 [2529-2529] | 39.5 [39.5-39.5] | 1311 [1311-1311] | 76.3 [76.3-76.3] | 849 [849-849] | 324 | yes |
| 200 | worker failed (rc=1) | | | | | | |
| 1024 | 23327 [23327-23327] | 43.9 [43.9-43.9] | 15667 [15667-15667] | 65.4 [65.4-65.4] | 10052 [10052-10052] | 354 | yes |
