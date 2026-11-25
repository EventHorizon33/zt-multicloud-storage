# End-to-end upload/download (http, memory providers)

Chunk size 1 MiB, replication as configured (R=2 of 3), 1 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T20:08:46+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 416 [416-416] | 12.0 [12.0-12.0] | 119 [119-119] | 42.0 [42.0-42.0] | 113 [113-113] | 109 | yes |
| 20 | 559 [559-559] | 35.8 [35.8-35.8] | 306 [306-306] | 65.4 [65.4-65.4] | 228 [228-228] | 126 | yes |
| 100 | 2847 [2847-2847] | 35.1 [35.1-35.1] | 1421 [1421-1421] | 70.4 [70.4-70.4] | 983 [983-983] | 222 | yes |
| 200 | 5248 [5248-5248] | 38.1 [38.1-38.1] | 2914 [2914-2914] | 68.6 [68.6-68.6] | 1855 [1855-1855] | 330 | yes |
| 1024 | 26527 [26527-26527] | 38.6 [38.6-38.6] | 14557 [14557-14557] | 70.3 [70.3-70.3] | 9049 [9049-9049] | 1146 | yes |
