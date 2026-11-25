# End-to-end upload/download (http, memory providers)

Chunk size 1 MiB, replication as configured (R=2 of 3), 1 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T20:01:25+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 182 [182-182] | 27.4 [27.4-27.4] | 108 [108-108] | 46.3 [46.3-46.3] | 102 [102-102] | 108 | yes |
| 20 | 593 [593-593] | 33.7 [33.7-33.7] | 345 [345-345] | 57.9 [57.9-57.9] | 263 [263-263] | 130 | yes |
| 100 | 3073 [3073-3073] | 32.5 [32.5-32.5] | 1420 [1420-1420] | 70.4 [70.4-70.4] | 929 [929-929] | 203 | yes |
| 200 | 5343 [5343-5343] | 37.4 [37.4-37.4] | 2818 [2818-2818] | 71.0 [71.0-71.0] | 1806 [1806-1806] | 305 | yes |
| 1024 | 26194 [26194-26194] | 39.1 [39.1-39.1] | 15156 [15156-15156] | 67.6 [67.6-67.6] | 10182 [10182-10182] | 1130 | yes |
