# End-to-end upload/download (http, memory providers)

Chunk size 4 MiB, replication as configured (R=2 of 3), 3 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T12:13:56+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 71 [69-74] | 70.8 [67.9-72.2] | 44 [42-49] | 113.6 [101.1-117.9] | 40 [39-43] | 111 | yes |
| 20 | 193 [189-194] | 103.5 [103.0-105.9] | 135 [127-139] | 147.8 [143.8-157.3] | 89 [88-95] | 146 | yes |
| 100 | 897 [888-927] | 111.4 [107.9-112.6] | 609 [594-630] | 164.2 [158.7-168.4] | 364 [336-369] | 235 | yes |
| 200 | 1701 [1658-1713] | 117.6 [116.7-120.6] | 1085 [1048-1159] | 184.3 [172.6-190.8] | 595 [590-656] | 339 | yes |
