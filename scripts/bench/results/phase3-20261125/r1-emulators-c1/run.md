# End-to-end upload/download (http, emulators providers)

Chunk size 1 MiB, replication as configured (R=2 of 3), 1 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T20:03:37+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 432 [432-432] | 11.6 [11.6-11.6] | 261 [261-261] | 19.1 [19.1-19.1] | 247 [247-247] | 145 | yes |
| 20 | 1579 [1579-1579] | 12.7 [12.7-12.7] | 594 [594-594] | 33.7 [33.7-33.7] | 515 [515-515] | 155 | yes |
| 100 | 7628 [7628-7628] | 13.1 [13.1-13.1] | 2418 [2418-2418] | 41.4 [41.4-41.4] | 1961 [1961-1961] | 165 | yes |
| 200 | 14612 [14612-14612] | 13.7 [13.7-13.7] | 4830 [4830-4830] | 41.4 [41.4-41.4] | 3612 [3612-3612] | 178 | yes |
| 1024 | 72273 [72273-72273] | 14.2 [14.2-14.2] | 25577 [25577-25577] | 40.0 [40.0-40.0] | 20640 [20640-20640] | 328 | yes |
