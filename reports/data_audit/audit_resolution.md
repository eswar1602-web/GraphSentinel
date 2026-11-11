# Audit resolution — `data\raw\CICIDS2017\TrafficLabelling`

## Per-file structure

| file | lines | CRLF | quotes | commas/line | comma-only lines | runs | FHL raw equal | FHL numeric equal |
|---|---:|---:|---:|---|---:|---|---|---|
| Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv | 225,746 | 0 | 0 | {84: 225746} | 0 | [] | 225,745/225,745 | True |
| Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv | 286,468 | 286,468 | 0 | {84: 286468} | 0 | [] | 286,467/286,467 | True |
| Friday-WorkingHours-Morning.pcap_ISCX.csv | 191,034 | 191,034 | 0 | {84: 191034} | 0 | [] | 191,033/191,033 | True |
| Monday-WorkingHours.pcap_ISCX.csv | 529,919 | 0 | 0 | {84: 529919} | 0 | [] | 529,918/529,918 | True |
| Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv | 288,603 | 288,603 | 0 | {84: 288603} | 0 | [] | 288,602/288,602 | True |
| Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv | 458,969 | 458,969 | 0 | {84: 458969} | 288,602 | [[170368, 458969]] | 170,366/170,366 | True |
| Tuesday-WorkingHours.pcap_ISCX.csv | 445,910 | 445,910 | 0 | {84: 445910} | 0 | [] | 445,909/445,909 | True |
| Wednesday-workingHours.pcap_ISCX.csv | 692,704 | 692,704 | 0 | {84: 692704} | 0 | [] | 692,703/692,703 | True |

## Timestamps

| file | dates | hours | secs | raw range | corrected range | back-jumps raw | back-jumps corr |
|---|---|---|---:|---|---|---:|---:|
| Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv | [[7, 7, 2017]] | [3, 4, 5] | 0.00 | ['03:30', '05:02'] | ['15:30', '17:02'] | 0.0000 | 0.0000 |
| Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv | [[7, 7, 2017]] | [1, 2, 3] | 0.00 | ['01:00', '03:29'] | ['13:00', '15:29'] | 0.0000 | 0.0000 |
| Friday-WorkingHours-Morning.pcap_ISCX.csv | [[7, 7, 2017]] | [8, 9, 10, 11, 12] | 0.00 | ['08:59', '12:59'] | ['08:59', '12:59'] | 0.0000 | 0.0000 |
| Monday-WorkingHours.pcap_ISCX.csv | [[3, 7, 2017]] | [1, 2, 3, 4, 5, 8, 9, 10, 11, 12] | 1.00 | ['01:00', '12:59'] | ['08:55', '17:01'] | 0.3215 | 0.3214 |
| Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv | [[6, 7, 2017]] | [1, 2, 3, 4, 5] | 0.00 | ['01:00', '05:04'] | ['13:00', '17:04'] | 0.0000 | 0.0000 |
| Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv | [[6, 7, 2017]] | [8, 9, 10, 11, 12] | 0.00 | ['08:59', '12:59'] | ['08:59', '12:59'] | 0.0000 | 0.0000 |
| Tuesday-WorkingHours.pcap_ISCX.csv | [[4, 7, 2017]] | [1, 2, 3, 4, 5, 8, 9, 10, 11, 12] | 0.00 | ['01:00', '12:59'] | ['08:53', '17:00'] | 0.3343 | 0.3343 |
| Wednesday-workingHours.pcap_ISCX.csv | [[5, 7, 2017]] | [1, 2, 3, 4, 5, 8, 9, 10, 11, 12] | 0.00 | ['01:00', '12:59'] | ['08:42', '17:10'] | 0.2165 | 0.2165 |

| label | file | rows | raw window | corrected window | published | corr in pub±5m | raw in pub±5m |
|---|---|---:|---|---|---|---:|---:|
| DDoS | Friday-WorkingHours-Afternoon-DDos | 128,027 | ['03:56', '04:16'] | ['15:56', '16:16'] | ['15:56', '16:16'] | 1.000 | 0.000 |
| PortScan | Friday-WorkingHours-Afternoon-PortScan | 158,930 | ['01:05', '03:23'] | ['13:05', '15:23'] | ['13:55', '15:29'] | 1.000 | 0.000 |
| Bot | Friday-WorkingHours-Morning | 1,966 | ['09:34', '12:59'] | ['09:34', '12:59'] | ['10:02', '11:02'] | 0.759 | 0.759 |
| Infiltration | Thursday-WorkingHours-Afternoon-Infilteration | 36 | ['02:19', '03:45'] | ['14:19', '15:45'] | ['14:19', '15:45'] | 1.000 | 0.000 |
| Web Attack – Brute Force | Thursday-WorkingHours-Morning-WebAttacks | 1,507 | ['09:15', '10:00'] | ['09:15', '10:00'] | ['09:20', '10:00'] | 1.000 | 1.000 |
| Web Attack – Sql Injection | Thursday-WorkingHours-Morning-WebAttacks | 21 | ['10:40', '10:42'] | ['10:40', '10:42'] | ['10:40', '10:42'] | 1.000 | 1.000 |
| Web Attack – XSS | Thursday-WorkingHours-Morning-WebAttacks | 652 | ['10:15', '10:35'] | ['10:15', '10:35'] | ['10:15', '10:35'] | 1.000 | 1.000 |
| FTP-Patator | Tuesday-WorkingHours | 7,938 | ['09:17', '10:30'] | ['09:17', '10:30'] | ['09:20', '10:20'] | 1.000 | 1.000 |
| SSH-Patator | Tuesday-WorkingHours | 5,897 | ['02:09', '03:11'] | ['14:09', '15:11'] | ['14:00', '15:00'] | 0.925 | 0.000 |
| DoS GoldenEye | Wednesday-workingHours | 10,293 | ['11:10', '11:19'] | ['11:10', '11:19'] | ['11:10', '11:23'] | 1.000 | 1.000 |
| DoS Hulk | Wednesday-workingHours | 231,073 | ['10:43', '11:07'] | ['10:43', '11:07'] | ['10:43', '11:00'] | 0.999 | 0.999 |
| DoS Slowhttptest | Wednesday-workingHours | 5,499 | ['10:15', '10:37'] | ['10:15', '10:37'] | ['10:14', '10:35'] | 1.000 | 1.000 |
| DoS slowloris | Wednesday-workingHours | 5,796 | ['02:24', '10:11'] | ['09:01', '14:25'] | ['09:47', '10:10'] | 0.999 | 0.999 |
| Heartbleed | Wednesday-workingHours | 11 | ['03:12', '03:32'] | ['15:12', '15:32'] | ['15:12', '15:32'] | 1.000 | 0.000 |

## Conflicting labels (features incl. Destination Port; identity excluded)

- **Friday-WorkingHours-Morning.pcap_ISCX.csv**: 0 groups / 0 rows {}; combos []. Without Destination Port: 2 groups / 10 rows {'Bot': 8, 'BENIGN': 2}
- **Wednesday-workingHours.pcap_ISCX.csv**: 48 groups / 1091 rows {'DoS Hulk': 1041, 'BENIGN': 49, 'DoS slowloris': 1}; combos [('BENIGN | DoS Hulk', 47), ('BENIGN | DoS slowloris', 1)]. Without Destination Port: 49 groups / 1093 rows {'DoS Hulk': 1042, 'BENIGN': 50, 'DoS slowloris': 1}
  - 352 rows {'DoS Hulk': 351, 'BENIGN': 1} | {'Destination Port': 80.0, 'Protocol': 6.0, 'Flow Duration': 0.0, 'Total Fwd Packets': 2.0, 'Total Backward Packets': 0.0, 'Total Length of Fwd Packets': 0.0, 'Total Length of Bwd Packets': 0.0, 'Init_Win_bytes_forward': 274.0, 'Init_Win_bytes_backward': -1.0} | ts ['5/7/2017 10:43', '5/7/2017 10:44', '5/7/2017 10:45'] | {'172.16.0.1 -> 192.168.10.50': 351, '192.168.10.19 -> 50.63.243.230': 1}
  - 132 rows {'DoS Hulk': 131, 'BENIGN': 1} | {'Destination Port': 80.0, 'Protocol': 6.0, 'Flow Duration': 49.0, 'Total Fwd Packets': 2.0, 'Total Backward Packets': 0.0, 'Total Length of Fwd Packets': 0.0, 'Total Length of Bwd Packets': 0.0, 'Init_Win_bytes_forward': 274.0, 'Init_Win_bytes_backward': -1.0} | ts ['5/7/2017 10:43', '5/7/2017 10:44', '5/7/2017 10:45'] | {'172.16.0.1 -> 192.168.10.50': 131, '192.168.10.17 -> 50.63.243.230': 1}
  - 81 rows {'DoS Hulk': 80, 'BENIGN': 1} | {'Destination Port': 80.0, 'Protocol': 6.0, 'Flow Duration': 994.0, 'Total Fwd Packets': 2.0, 'Total Backward Packets': 0.0, 'Total Length of Fwd Packets': 0.0, 'Total Length of Bwd Packets': 0.0, 'Init_Win_bytes_forward': 274.0, 'Init_Win_bytes_backward': -1.0} | ts ['5/7/2017 10:43', '5/7/2017 10:44', '5/7/2017 10:45'] | {'172.16.0.1 -> 192.168.10.50': 80, '192.168.10.51 -> 72.167.18.239': 1}
  - 61 rows {'DoS Hulk': 60, 'BENIGN': 1} | {'Destination Port': 80.0, 'Protocol': 6.0, 'Flow Duration': 223.0, 'Total Fwd Packets': 2.0, 'Total Backward Packets': 0.0, 'Total Length of Fwd Packets': 0.0, 'Total Length of Bwd Packets': 0.0, 'Init_Win_bytes_forward': 251.0, 'Init_Win_bytes_backward': -1.0} | ts ['5/7/2017 10:43', '5/7/2017 10:44', '5/7/2017 10:45'] | {'172.16.0.1 -> 192.168.10.50': 60, '192.168.10.19 -> 211.233.74.132': 1}
  - 46 rows {'DoS Hulk': 45, 'BENIGN': 1} | {'Destination Port': 80.0, 'Protocol': 6.0, 'Flow Duration': 225.0, 'Total Fwd Packets': 2.0, 'Total Backward Packets': 0.0, 'Total Length of Fwd Packets': 0.0, 'Total Length of Bwd Packets': 0.0, 'Init_Win_bytes_forward': 251.0, 'Init_Win_bytes_backward': -1.0} | ts ['5/7/2017 10:43', '5/7/2017 10:44', '5/7/2017 10:45'] | {'172.16.0.1 -> 192.168.10.50': 45, '192.168.10.19 -> 211.233.74.132': 1}
  - 36 rows {'DoS Hulk': 35, 'BENIGN': 1} | {'Destination Port': 80.0, 'Protocol': 6.0, 'Flow Duration': 216.0, 'Total Fwd Packets': 2.0, 'Total Backward Packets': 0.0, 'Total Length of Fwd Packets': 0.0, 'Total Length of Bwd Packets': 0.0, 'Init_Win_bytes_forward': 251.0, 'Init_Win_bytes_backward': -1.0} | ts ['5/7/2017 10:43', '5/7/2017 10:44', '5/7/2017 10:45'] | {'172.16.0.1 -> 192.168.10.50': 35, '192.168.10.19 -> 211.233.74.132': 1}
  - 28 rows {'DoS Hulk': 27, 'BENIGN': 1} | {'Destination Port': 80.0, 'Protocol': 6.0, 'Flow Duration': 971.0, 'Total Fwd Packets': 2.0, 'Total Backward Packets': 0.0, 'Total Length of Fwd Packets': 0.0, 'Total Length of Bwd Packets': 0.0, 'Init_Win_bytes_forward': 274.0, 'Init_Win_bytes_backward': -1.0} | ts ['5/7/2017 10:44', '5/7/2017 10:45', '5/7/2017 10:46'] | {'172.16.0.1 -> 192.168.10.50': 27, '192.168.10.19 -> 50.63.243.230': 1}
  - 24 rows {'DoS Hulk': 23, 'BENIGN': 1} | {'Destination Port': 80.0, 'Protocol': 6.0, 'Flow Duration': 50.0, 'Total Fwd Packets': 2.0, 'Total Backward Packets': 0.0, 'Total Length of Fwd Packets': 0.0, 'Total Length of Bwd Packets': 0.0, 'Init_Win_bytes_forward': 251.0, 'Init_Win_bytes_backward': -1.0} | ts ['5/7/2017 10:44', '5/7/2017 10:45', '5/7/2017 10:46'] | {'172.16.0.1 -> 192.168.10.50': 23, '192.168.10.19 -> 178.255.83.1': 1}

## Negative Flow Duration

- Rows: 115; by label {'BENIGN': 115}; values {-1.0: 109, -12.0: 2, -2.0: 2, -13.0: 1, -4.0: 1}
- With negative rate: 115; with negative IAT: 115

## Exact duplicates and Flow IDs

| file | extra copies | adjacent | by label | rows w/ repeated FlowID | FlowIDs both dirs | same FlowID+ts rows | multi-label FlowIDs |
|---|---:|---:|---|---:|---:|---:|---:|
| Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv | 2 | 2 | {'BENIGN': 2} | 202,584 | 28,585 | 150,937 | 20,055 |
| Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv | 1 | 0 | {'BENIGN': 1} | 91,551 | 19,164 | 41,165 | 130 |
| Friday-WorkingHours-Morning.pcap_ISCX.csv | 2 | 0 | {'BENIGN': 2} | 139,209 | 28,394 | 58,694 | 0 |
| Monday-WorkingHours.pcap_ISCX.csv | 34 | 24 | {'BENIGN': 34} | 436,613 | 92,630 | 111,386 | 0 |
| Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv | 142 | 27 | {'BENIGN': 142} | 167,520 | 35,892 | 77,488 | 0 |
| Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv | 1 | 1 | {'BENIGN': 1} | 126,791 | 26,494 | 52,736 | 1,833 |
| Tuesday-WorkingHours.pcap_ISCX.csv | 4 | 3 | {'BENIGN': 4} | 363,764 | 70,825 | 166,595 | 1,600 |
| Wednesday-workingHours.pcap_ISCX.csv | 17 | 13 | {'BENIGN': 16, 'DoS Hulk': 1} | 603,976 | 74,222 | 298,540 | 12,160 |

## Cross-file

```
{
 "distinct_content_rows_shared": 33548,
 "rows_involved": 139720,
 "rows_involved_by_label": {
  "BENIGN": 139720
 },
 "file_combinations_top": [
  [
   "Tuesday-WorkingHours & Wednesday-workingHours",
   3523
  ],
  [
   "Thursday-WorkingHours-Afternoon-Infilteration & Wednesday-workingHours",
   2194
  ],
  [
   "Friday-WorkingHours-Morning & Wednesday-workingHours",
   2106
  ],
  [
   "Thursday-WorkingHours-Morning-WebAttacks & Wednesday-workingHours",
   1767
  ],
  [
   "Friday-WorkingHours-Morning & Tuesday-WorkingHours",
   1416
  ],
  [
   "Thursday-WorkingHours-Afternoon-Infilteration & Tuesday-WorkingHours",
   1387
  ],
  [
   "Friday-WorkingHours-Afternoon-PortScan & Wednesday-workingHours",
   1284
  ],
  [
   "Thursday-WorkingHours-Morning-WebAttacks & Tuesday-WorkingHours",
   1211
  ],
  [
   "Friday-WorkingHours-Afternoon-PortScan & Tuesday-WorkingHours",
   1028
  ],
  [
   "Thursday-WorkingHours-Afternoon-Infilteration & Thursday-WorkingHours-Morning-WebAttacks",
   909
  ]
 ],
 "shared_rows_packets_quantiles": {
  "0.5": 4.0,
  "0.9": 4.0,
  "0.99": 13.0
 },
 "shared_rows_duration_us_quantiles": {
  "0.5": 163.0,
  "0.9": 257.0,
  "0.99": 95018.0
 },
 "shared_rows_top_dst_ports": {
  "53.0": 85954,
  "443.0": 24417,
  "80.0": 13104,
  "137.0": 4373,
  "22.0": 3304
 },
 "feature_vectors_with_conflicting_labels_across_files": 663,
 "flow_ids_in_multiple_files": 150961
}
```

## Label mapping

| raw (repr) | rows | fine | family | binary |
|---|---:|---|---|---:|
| 'DDoS' | 128,027 | DDoS | DDoS | 1 |
| 'BENIGN' | 2,273,097 | BENIGN | Benign | 0 |
| 'PortScan' | 158,930 | PortScan | PortScan | 1 |
| 'Bot' | 1,966 | Bot | Bot | 1 |
| 'Infiltration' | 36 | Infiltration | Infiltration | 1 |
| 'Web Attack – Brute Force' | 1,507 | Web Attack - Brute Force | WebAttack | 1 |
| 'Web Attack – XSS' | 652 | Web Attack - XSS | WebAttack | 1 |
| 'Web Attack – Sql Injection' | 21 | Web Attack - SQL Injection | WebAttack | 1 |
| 'FTP-Patator' | 7,938 | FTP-Patator | BruteForce | 1 |
| 'SSH-Patator' | 5,897 | SSH-Patator | BruteForce | 1 |
| 'DoS Hulk' | 231,073 | DoS Hulk | DoS | 1 |
| 'DoS GoldenEye' | 10,293 | DoS GoldenEye | DoS | 1 |
| 'DoS slowloris' | 5,796 | DoS slowloris | DoS | 1 |
| 'DoS Slowhttptest' | 5,499 | DoS Slowhttptest | DoS | 1 |
| 'Heartbleed' | 11 | Heartbleed | Heartbleed | 1 |

Errors: none
