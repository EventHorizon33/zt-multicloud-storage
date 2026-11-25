WARNING: round 2 emulators c16 200 MiB: worker failed (rc=1)
# Before / after: 1 MiB (framework default) vs 16 MiB (deployment setting) chunks

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM; Python 3.12.3; commit 22c1a64; Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Method: real uvicorn server on loopback, fresh server per measurement after an untimed 1 MiB warm-up; 5 rounds, each round measures both chunk sizes back to back, alternating which goes first. Cells are median [min-max] over rounds; speed-up = same-round time(1 MiB) / time(16 MiB).
- Integrity: every measured transfer was verified byte-for-byte against the source.

## memory providers

| File | Upload, 1 MiB chunks (ms) | Upload, 16 MiB chunks (ms) | Upload speed-up | Download, 1 MiB (ms) | Download, 16 MiB (ms) | Download speed-up |
|---:|---:|---:|---:|---:|---:|---:|
| 5 MiB | 215 [182-450] | 132 [118-144] | **1.83 [1.29-3.19]x** | 110 [103-124] | 86 [77-252] | **1.28 [0.41-1.43]x** |
| 20 MiB | 640 [559-671] | 374 [351-452] | **1.68 [1.31-1.91]x** | 340 [306-384] | 263 [237-290] | **1.29 [1.22-1.34]x** |
| 100 MiB | 2857 [2783-3073] | 1449 [1387-1480] | **2.04 [1.89-2.08]x** | 1421 [1396-1552] | 1062 [1038-1171] | **1.34 [1.21-1.48]x** |
| 200 MiB | 5340 [5130-5490] | 2959 [2762-2962] | **1.85 [1.73-1.90]x** | 2913 [2599-2977] | 2055 [2026-2223] | **1.39 [1.26-1.42]x** |
| 1024 MiB | 26527 [25453-27021] | 14366 [13403-14527] | **1.84 [1.77-1.98]x** | 14557 [14361-15156] | 11289 [10474-11722] | **1.29 [1.26-1.38]x** |

Server peak RSS (MiB, max over rounds) and throughput at 16 MiB chunks:

| File | RSS 1 MiB | RSS 16 MiB | Upload MiB/s, 16 MiB | Download MiB/s, 16 MiB |
|---:|---:|---:|---:|---:|
| 5 MiB | 109 | 107 | 37.9 [34.7-42.5] | 58.0 [19.9-64.7] |
| 20 MiB | 131 | 151 | 53.4 [44.2-57.0] | 76.2 [69.0-84.4] |
| 100 MiB | 222 | 252 | 69.0 [67.6-72.1] | 94.2 [85.4-96.3] |
| 200 MiB | 330 | 363 | 67.6 [67.5-72.4] | 97.3 [90.0-98.7] |
| 1024 MiB | 1146 | 1196 | 71.3 [70.5-76.4] | 90.7 [87.4-97.8] |

Drift check, 100 MiB upload at 1 MiB chunks by round (ms): r1=3073, r2=2847, r3=2857, r4=2938, r5=2783

## emulators providers

| File | Upload, 1 MiB chunks (ms) | Upload, 16 MiB chunks (ms) | Upload speed-up | Download, 1 MiB (ms) | Download, 16 MiB (ms) | Download speed-up |
|---:|---:|---:|---:|---:|---:|---:|
| 5 MiB | 416 [388-481] | 232 [195-563] | **1.87 [0.77-2.13]x** | 180 [145-261] | 101 [84-120] | **1.86 [1.33-2.18]x** |
| 20 MiB | 1579 [1542-1595] | 907 [604-991] | **1.74 [1.59-2.55]x** | 593 [539-622] | 311 [287-371] | **1.79 [1.53-2.17]x** |
| 100 MiB | 7615 [7385-7688] | 2488 [1638-2603] | **3.04 [2.88-4.65]x** | 2441 [2418-2504] | 1381 [829-1490] | **1.77 [1.62-2.92]x** |
| 200 MiB | 14907 [14612-15147] | 4945 [4691-5043] | **3.04 [2.90-3.17]x** | 4976 [4830-5100] | 2861 [2832-2964] | **1.72 [1.69-1.78]x** |
| 1024 MiB | 77756 [72273-78565] | 23501 [23207-24356] | **3.29 [3.11-3.34]x** | 26227 [24247-27744] | 15736 [14398-16666] | **1.67 [1.63-1.70]x** |

Server peak RSS (MiB, max over rounds) and throughput at 16 MiB chunks:

| File | RSS 1 MiB | RSS 16 MiB | Upload MiB/s, 16 MiB | Download MiB/s, 16 MiB |
|---:|---:|---:|---:|---:|
| 5 MiB | 154 | 176 | 21.6 [8.9-25.6] | 49.6 [41.8-59.5] |
| 20 MiB | 157 | 256 | 22.0 [20.2-33.1] | 64.4 [53.9-69.8] |
| 100 MiB | 169 | 325 | 40.2 [38.4-61.1] | 72.4 [67.1-120.6] |
| 200 MiB | 198 | 323 | 40.5 [39.7-42.6] | 69.9 [67.5-70.6] |
| 1024 MiB | 374 | 373 | 43.6 [42.0-44.1] | 65.1 [61.4-71.1] |

Drift check, 100 MiB upload at 1 MiB chunks by round (ms): r1=7628, r2=7688, r3=7385, r4=7501, r5=7615

## Where the cipher sits in the total (same session)

Cipher-only throughput (single thread, 1 MiB chunks, no I/O) next to measured end-to-end time at 16 MiB chunks, in-memory providers.

| File | Encrypt MiB/s | Decrypt MiB/s | Encrypt share of upload | Decrypt share of download |
|---:|---:|---:|---:|---:|
| 5 MiB | 532 | 653 | 7% | 9% |
| 20 MiB | 663 | 711 | 8% | 11% |
| 100 MiB | 628 | 701 | 11% | 13% |
| 200 MiB | 631 | 690 | 11% | 14% |
| 1024 MiB | 654 | 716 | 11% | 13% |

