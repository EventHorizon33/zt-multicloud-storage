# End-to-end upload/download (http, emulators providers)

Chunk size 1 MiB, replication as configured (R=2 of 3), 3 repeats per size, fresh server per repeat after an untimed 1 MiB warm-up. Cells are `median [min-max]`.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T12:06:47+00:00

| Size (MiB) | Upload ms | Upload MiB/s | Download ms | Download MiB/s | Download TTFB ms | Server peak RSS MiB | Verified |
|---:|---:|---:|---:|---:|---:|---:|:--:|
| 5 | 220 [197-226] | 22.7 [22.1-25.3] | 71 [68-73] | 70.4 [68.1-73.5] | 66 [65-71] | 150 | yes |
| 20 | 795 [774-797] | 25.2 [25.1-25.8] | 260 [257-261] | 77.0 [76.5-77.8] | 222 [220-225] | 164 | yes |
| 100 | 3644 [3614-3647] | 27.4 [27.4-27.7] | 1067 [1042-1083] | 93.7 [92.3-96.0] | 856 [829-859] | 179 | yes |
| 200 | 7217 [7136-7398] | 27.7 [27.0-28.0] | 2118 [2099-2172] | 94.4 [92.1-95.3] | 1670 [1660-1738] | 189 | yes |
