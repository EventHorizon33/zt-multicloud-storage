# End-to-end upload/download (http, memory providers)

Chunk size 32 MiB, replication as configured (R=2 of 3), 3 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T12:23:03+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 63 [62-68] | 79.6 [73.0-80.6] | 42 [36-42] | 118.8 [118.5-137.7] | 39 [33-39] | 108 | yes |
| 20 | 179 [176-192] | 112.0 [104.1-113.7] | 111 [111-127] | 179.4 [158.0-179.7] | 75 [74-82] | 152 | yes |
| 100 | 794 [788-800] | 126.0 [125.0-126.9] | 554 [537-618] | 180.6 [161.8-186.2] | 336 [322-346] | 290 | yes |
| 200 | 1546 [1530-1549] | 129.3 [129.2-130.7] | 1080 [1046-1088] | 185.2 [183.9-191.1] | 605 [591-646] | 394 | yes |
