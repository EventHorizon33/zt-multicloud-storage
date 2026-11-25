# End-to-end upload/download (http, emulators providers)

Chunk size 64 MiB, replication as configured (R=2 of 3), 2 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T12:28:03+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 1024 | 21651 [21108-22193] | 47.3 [46.1-48.5] | 10180 [9620-10739] | 100.9 [95.4-106.4] | 6993 [6621-7365] | 615 | yes |
