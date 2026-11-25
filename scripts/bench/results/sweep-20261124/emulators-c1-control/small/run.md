# End-to-end upload/download (http, emulators providers)

Chunk size 1 MiB, replication as configured (R=2 of 3), 3 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T12:30:06+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 221 [219-230] | 22.6 [21.7-22.9] | 73 [72-74] | 68.1 [67.6-69.5] | 71 [69-71] | 145 | yes |
| 20 | 868 [841-913] | 23.0 [21.9-23.8] | 275 [273-280] | 72.8 [71.5-73.1] | 231 [230-235] | 163 | yes |
| 100 | 4327 [3930-4337] | 23.1 [23.1-25.4] | 1182 [1151-1433] | 84.6 [69.8-86.9] | 938 [922-1152] | 173 | yes |
| 200 | 8120 [7661-8337] | 24.6 [24.0-26.1] | 2411 [2325-2445] | 83.0 [81.8-86.0] | 1898 [1837-1954] | 211 | yes |
