# Per-size breakdown: upload, encryption, decryption, download

- Machine: Intel(R) Core(TM) Ultra 9 185H, 22 logical CPUs, 15704 MiB RAM; Python 3.12.3; commit 22c1a64; Linux-6.18.33.2-microsoft-standard-WSL2-x86_64-with-glibc2.39
- Start state: load average 1.11, 14828 MiB memory available, 923 GiB disk free
- Cells are `median [95% bootstrap CI of the median]` over n measurements. Encryption and decryption are the in-server time inside encrypt_chunk (AES-256-GCM plus SHA-256 of the blob) and decrypt_chunk (SHA-256 check plus AES-256-GCM verify), summed over the file's chunks. Upload and download are whole-request wall times.
- Unverified transfers: 0


## emulators providers, 1 MiB chunks

| File | n | Upload | Encryption | Decryption | Download | Encrypt share of upload | Decrypt share of download |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 5 MiB | 10 | 482 ms [463 ms-503 ms] | 11 ms [10 ms-11 ms] | 12 ms [10 ms-13 ms] | 194 ms [181 ms-203 ms] | 2% | 6% |
| 20 MiB | 10 | 1.63 s [1.58 s-1.73 s] | 35 ms [33 ms-40 ms] | 39 ms [34 ms-41 ms] | 576 ms [568 ms-585 ms] | 2% | 6% |
| 100 MiB | 10 | 7.69 s [7.63 s-7.82 s] | 172 ms [168 ms-175 ms] | 173 ms [172 ms-180 ms] | 2.41 s [2.39 s-2.48 s] | 2% | 7% |
| 200 MiB | 10 | 15.1 s [14.8 s-15.2 s] | 340 ms [329 ms-352 ms] | 353 ms [348 ms-360 ms] | 5.00 s [4.88 s-5.17 s] | 2% | 7% |
| 1024 MiB | 5 | 76.9 s [76.2 s-77.0 s] | 1.73 s [1.66 s-1.76 s] | 1.76 s [1.75 s-1.80 s] | 24.6 s [24.3 s-25.7 s] | 2% | 7% |

Where the rest of the upload goes (median, ms; request thread):

| File | Replication | Metadata commits | Audit | Plaintext SHA-256 | Body read |
|---:|---:|---:|---:|---:|---:|
| 5 MiB | 310 | 64 | 45 | 5 | 14 |
| 20 MiB | 1147 | 191 | 127 | 21 | 59 |
| 100 MiB | 5623 | 858 | 508 | 108 | 288 |
| 200 MiB | 11465 | 1342 | 840 | 217 | 552 |
| 1024 MiB | 60606 | 5532 | 3858 | 1058 | 2815 |

Where the rest of the download goes (median, ms; request thread):

| File | Fetch and verify replica | Audit | Plaintext hash and spool write | Time to first byte |
|---:|---:|---:|---:|---:|
| 5 MiB | 99 | 41 | 6 | 185 |
| 20 MiB | 340 | 110 | 47 | 481 |
| 100 MiB | 1491 | 320 | 217 | 1936 |
| 200 MiB | 3146 | 661 | 397 | 3965 |
| 1024 MiB | 15675 | 3768 | 2029 | 19665 |

## emulators providers, 16 MiB chunks

| File | n | Upload | Encryption | Decryption | Download | Encrypt share of upload | Decrypt share of download |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 5 MiB | 10 | 433 ms [299 ms-473 ms] | 12 ms [12 ms-13 ms] | 9 ms [8 ms-10 ms] | 134 ms [125 ms-164 ms] | 3% | 7% |
| 20 MiB | 10 | 740 ms [626 ms-877 ms] | 52 ms [50 ms-56 ms] | 47 ms [45 ms-51 ms] | 344 ms [327 ms-384 ms] | 7% | 14% |
| 100 MiB | 10 | 2.72 s [2.65 s-2.78 s] | 160 ms [156 ms-162 ms] | 161 ms [158 ms-165 ms] | 1.52 s [1.46 s-1.56 s] | 6% | 11% |
| 200 MiB | 10 | 4.95 s [4.87 s-5.08 s] | 328 ms [320 ms-369 ms] | 332 ms [324 ms-348 ms] | 3.01 s [2.94 s-3.08 s] | 7% | 11% |
| 1024 MiB | 5 | 23.3 s [21.2 s-23.4 s] | 1.61 s [1.59 s-2.00 s] | 1.68 s [1.66 s-1.71 s] | 14.9 s [13.9 s-16.1 s] | 7% | 11% |

Where the rest of the upload goes (median, ms; request thread):

| File | Replication | Metadata commits | Audit | Plaintext SHA-256 | Body read |
|---:|---:|---:|---:|---:|---:|
| 5 MiB | 310 | 37 | 23 | 5 | 26 |
| 20 MiB | 476 | 50 | 32 | 20 | 83 |
| 100 MiB | 1931 | 101 | 79 | 98 | 302 |
| 200 MiB | 3534 | 160 | 140 | 198 | 509 |
| 1024 MiB | 16400 | 728 | 720 | 981 | 2146 |

Where the rest of the download goes (median, ms; request thread):

| File | Fetch and verify replica | Audit | Plaintext hash and spool write | Time to first byte |
|---:|---:|---:|---:|---:|
| 5 MiB | 38 | 20 | 7 | 126 |
| 20 MiB | 100 | 25 | 36 | 247 |
| 100 MiB | 583 | 72 | 180 | 989 |
| 200 MiB | 1119 | 139 | 403 | 1950 |
| 1024 MiB | 5460 | 774 | 2011 | 9371 |

## memory providers, 1 MiB chunks

| File | n | Upload | Encryption | Decryption | Download | Encrypt share of upload | Decrypt share of download |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 5 MiB | 10 | 213 ms [204 ms-235 ms] | 10 ms [9 ms-11 ms] | 10 ms [10 ms-12 ms] | 135 ms [130 ms-141 ms] | 5% | 8% |
| 20 MiB | 10 | 616 ms [592 ms-631 ms] | 34 ms [33 ms-44 ms] | 33 ms [31 ms-34 ms] | 377 ms [364 ms-383 ms] | 6% | 9% |
| 100 MiB | 10 | 2.81 s [2.72 s-3.11 s] | 195 ms [162 ms-226 ms] | 157 ms [152 ms-161 ms] | 1.41 s [1.39 s-1.43 s] | 7% | 11% |
| 200 MiB | 10 | 5.07 s [4.97 s-5.33 s] | 338 ms [329 ms-472 ms] | 317 ms [307 ms-321 ms] | 2.76 s [2.67 s-2.91 s] | 7% | 11% |
| 1024 MiB | 5 | 25.7 s [25.1 s-26.1 s] | 1.72 s [1.66 s-2.74 s] | 1.63 s [1.56 s-1.69 s] | 14.0 s [13.4 s-15.0 s] | 7% | 11% |

Where the rest of the upload goes (median, ms; request thread):

| File | Replication | Metadata commits | Audit | Plaintext SHA-256 | Body read |
|---:|---:|---:|---:|---:|---:|
| 5 MiB | 48 | 67 | 40 | 5 | 19 |
| 20 MiB | 172 | 182 | 103 | 19 | 67 |
| 100 MiB | 847 | 825 | 438 | 98 | 303 |
| 200 MiB | 1707 | 1203 | 697 | 200 | 698 |
| 1024 MiB | 8797 | 5379 | 3525 | 1010 | 4060 |

Where the rest of the download goes (median, ms; request thread):

| File | Fetch and verify replica | Audit | Plaintext hash and spool write | Time to first byte |
|---:|---:|---:|---:|---:|
| 5 MiB | 46 | 44 | 10 | 127 |
| 20 MiB | 134 | 106 | 44 | 276 |
| 100 MiB | 457 | 262 | 209 | 887 |
| 200 MiB | 934 | 541 | 418 | 1746 |
| 1024 MiB | 5188 | 3016 | 1963 | 8962 |

## memory providers, 16 MiB chunks

| File | n | Upload | Encryption | Decryption | Download | Encrypt share of upload | Decrypt share of download |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 5 MiB | 10 | 158 ms [151 ms-166 ms] | 12 ms [12 ms-13 ms] | 13 ms [11 ms-13 ms] | 110 ms [98 ms-117 ms] | 8% | 11% |
| 20 MiB | 10 | 399 ms [395 ms-422 ms] | 51 ms [49 ms-53 ms] | 41 ms [39 ms-49 ms] | 296 ms [285 ms-308 ms] | 13% | 14% |
| 100 MiB | 10 | 1.46 s [1.45 s-1.48 s] | 162 ms [159 ms-215 ms] | 169 ms [167 ms-174 ms] | 1.11 s [1.09 s-1.16 s] | 11% | 15% |
| 200 MiB | 10 | 2.73 s [2.68 s-2.88 s] | 342 ms [326 ms-436 ms] | 327 ms [323 ms-337 ms] | 2.13 s [2.06 s-2.27 s] | 12% | 15% |
| 1024 MiB | 5 | 14.0 s [13.8 s-14.3 s] | 1.64 s [1.61 s-2.66 s] | 1.66 s [1.63 s-1.69 s] | 10.4 s [10.3 s-11.7 s] | 12% | 16% |

Where the rest of the upload goes (median, ms; request thread):

| File | Replication | Metadata commits | Audit | Plaintext SHA-256 | Body read |
|---:|---:|---:|---:|---:|---:|
| 5 MiB | 38 | 36 | 20 | 5 | 21 |
| 20 MiB | 138 | 52 | 28 | 19 | 80 |
| 100 MiB | 695 | 87 | 80 | 96 | 301 |
| 200 MiB | 1354 | 145 | 128 | 192 | 563 |
| 1024 MiB | 6878 | 748 | 673 | 980 | 2743 |

Where the rest of the download goes (median, ms; request thread):

| File | Fetch and verify replica | Audit | Plaintext hash and spool write | Time to first byte |
|---:|---:|---:|---:|---:|
| 5 MiB | 13 | 16 | 6 | 102 |
| 20 MiB | 39 | 27 | 40 | 199 |
| 100 MiB | 165 | 57 | 203 | 602 |
| 200 MiB | 307 | 101 | 390 | 1115 |
| 1024 MiB | 1550 | 334 | 2118 | 5421 |
