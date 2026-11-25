# Cipher pipeline alone (chunk 1 MiB)

5 repeats, single thread, data in memory, no I/O. Cells are `median [min-max]` in MiB/s. `encrypt` = AES-256-GCM with AAD + SHA-256 of the blob; `decrypt` = SHA-256 check + GCM verify.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T10:19:19+00:00

| Size (MiB) | Chunks | Split | Encrypt | Decrypt | Raw AES-GCM | Raw SHA-256 |
|---:|---:|---:|---:|---:|---:|---:|
| 5 | 5 | 6380 [684-7771] | 429 [208-749] | 622 [469-732] | 3203 [2965-3314] | 1057 [803-1128] |
| 20 | 20 | 4844 [968-5065] | 597 [350-669] | 647 [607-718] | 2675 [1683-3236] | 1055 [1034-1140] |
| 100 | 100 | 6259 [1110-6806] | 594 [340-680] | 708 [632-717] | 2801 [2092-3102] | 1043 [901-1060] |
| 200 | 200 | 6590 [6063-7097] | 643 [358-660] | 700 [664-747] | 2809 [2673-3048] | 1029 [976-1056] |
| 1024 | 1024 | 5687 [791-6400] | 621 [369-657] | 706 [688-759] | 2679 [2593-3108] | 1083 [1003-1141] |
