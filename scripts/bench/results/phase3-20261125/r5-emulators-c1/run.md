# End-to-end upload/download (http, emulators providers)

Chunk size 1 MiB, replication as configured (R=2 of 3), 1 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T20:29:34+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 405 [405-405] | 12.4 [12.4-12.4] | 180 [180-180] | 27.8 [27.8-27.8] | 173 [173-173] | 150 | yes |
| 20 | 1591 [1591-1591] | 12.6 [12.6-12.6] | 622 [622-622] | 32.1 [32.1-32.1] | 542 [542-542] | 152 | yes |
| 100 | 7615 [7615-7615] | 13.1 [13.1-13.1] | 2419 [2419-2419] | 41.3 [41.3-41.3] | 1889 [1889-1889] | 166 | yes |
| 200 | 14955 [14955-14955] | 13.4 [13.4-13.4] | 5100 [5100-5100] | 39.2 [39.2-39.2] | 4147 [4147-4147] | 184 | yes |
| 1024 | 77917 [77917-77917] | 13.1 [13.1-13.1] | 24247 [24247-24247] | 42.2 [42.2-42.2] | 19078 [19078-19078] | 334 | yes |
