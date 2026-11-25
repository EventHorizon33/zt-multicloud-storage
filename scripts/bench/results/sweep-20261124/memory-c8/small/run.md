# End-to-end upload/download (http, memory providers)

Chunk size 8 MiB, replication as configured (R=2 of 3), 3 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T12:17:42+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 63 [63-70] | 79.2 [71.7-79.8] | 41 [41-42] | 122.6 [119.6-122.9] | 38 [37-39] | 107 | yes |
| 20 | 192 [184-200] | 104.4 [99.8-108.5] | 132 [127-153] | 151.7 [130.5-158.0] | 84 [84-102] | 162 | yes |
| 100 | 771 [761-795] | 129.7 [125.8-131.5] | 539 [513-550] | 185.4 [181.9-195.0] | 304 [296-312] | 259 | yes |
| 200 | 1488 [1470-1499] | 134.4 [133.4-136.0] | 1080 [1030-1112] | 185.2 [179.9-194.2] | 554 [548-623] | 363 | yes |
