# Cipher pipeline alone (chunk 1 MiB)

5 repeats, single thread, data in memory, no I/O. Cells are `median [min-max]` in MiB/s. `encrypt` = AES-256-GCM with AAD + SHA-256 of the blob; `decrypt` = SHA-256 check + GCM verify.

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM
- Software: Python 3.12.3, cryptography 50.0.2, FastAPI 0.162.5, uvicorn 0.54.0
- Platform: Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Commit: 22c1a64; run at 2026-11-24T20:00:46+00:00

| Size (MiB) | Chunks | Split | Encrypt | Decrypt | Raw AES-GCM | Raw SHA-256 |
|---:|---:|---:|---:|---:|---:|---:|
| 5 | 5 | 5451 [927-8512] | 532 [344-630] | 653 [551-763] | 2792 [2622-3342] | 1055 [1011-1132] |
| 20 | 20 | 4852 [1487-5086] | 663 [381-685] | 711 [678-731] | 2937 [2762-3236] | 1061 [1005-1105] |
| 100 | 100 | 5568 [887-6073] | 628 [362-658] | 701 [671-716] | 2740 [2498-3197] | 1006 [951-1041] |
| 200 | 200 | 6036 [5091-6648] | 631 [312-641] | 690 [643-700] | 2963 [2852-3042] | 1015 [965-1061] |
| 1024 | 1024 | 6294 [1057-7092] | 654 [418-747] | 716 [692-723] | 2882 [2815-3018] | 1027 [1019-1162] |
