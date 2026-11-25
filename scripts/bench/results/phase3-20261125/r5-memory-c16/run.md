# End-to-end upload/download (http, memory providers)

Chunk size 16 MiB, replication as configured (R=2 of 3), 1 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T20:28:39+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 144 [144-144] | 34.7 [34.7-34.7] | 100 [100-100] | 50.1 [50.1-50.1] | 88 [88-88] | 107 | yes |
| 20 | 359 [359-359] | 55.8 [55.8-55.8] | 290 [290-290] | 69.0 [69.0-69.0] | 199 [199-199] | 151 | yes |
| 100 | 1473 [1473-1473] | 67.9 [67.9-67.9] | 1095 [1095-1095] | 91.3 [91.3-91.3] | 592 [592-592] | 246 | yes |
| 200 | 2807 [2807-2807] | 71.2 [71.2-71.2] | 2223 [2223-2223] | 90.0 [90.0-90.0] | 1173 [1173-1173] | 347 | yes |
| 1024 | 13992 [13992-13992] | 73.2 [73.2-73.2] | 11109 [11109-11109] | 92.2 [92.2-92.2] | 5338 [5338-5338] | 1195 | yes |
