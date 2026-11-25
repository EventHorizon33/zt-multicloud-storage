# End-to-end upload/download (http, memory providers)

Chunk size 2 MiB, replication as configured (R=2 of 3), 2 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T12:10:32+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 1024 | 9674 [9520-9827] | 105.9 [104.2-107.6] | 6307 [6202-6412] | 162.4 [159.7-165.1] | 3609 [3587-3631] | 1186 | yes |
