# End-to-end upload/download (http, memory providers)

Chunk size 1 MiB, replication as configured (R=2 of 3), 3 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T12:29:29+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 89 [88-96] | 56.2 [52.4-57.0] | 60 [47-61] | 83.4 [82.2-107.0] | 55 [44-57] | 109 | yes |
| 20 | 321 [297-332] | 62.4 [60.3-67.3] | 176 [173-185] | 113.5 [108.3-115.6] | 132 [125-135] | 126 | yes |
| 100 | 1499 [1480-1534] | 66.7 [65.2-67.6] | 693 [682-721] | 144.2 [138.6-146.6] | 452 [447-484] | 222 | yes |
| 200 | 2714 [2694-2776] | 73.7 [72.0-74.2] | 1352 [1346-1354] | 148.0 [147.7-148.6] | 860 [860-860] | 308 | yes |
