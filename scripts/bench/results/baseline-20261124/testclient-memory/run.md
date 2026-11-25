# End-to-end upload/download (testclient, memory providers)

Chunk size 1 MiB, replication as configured (R=2 of 3), 5 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T10:24:48+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 162 [149-196] | 30.8 [25.5-33.6] | 126 [119-141] | 39.8 [35.5-42.0] | n/a | n/a | yes |
| 20 | 521 [488-760] | 38.4 [26.3-41.0] | 462 [443-480] | 43.3 [41.6-45.1] | n/a | n/a | yes |
| 100 | 2748 [2467-2862] | 36.4 [34.9-40.5] | 2075 [2004-2262] | 48.2 [44.2-49.9] | n/a | n/a | yes |
