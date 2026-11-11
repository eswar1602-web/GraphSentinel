# CICIDS2017 raw data audit — `data\raw\CICIDS2017\TrafficLabelling`

- Files: 8  |  rows parsed: 3,119,345  |  non-empty: 2,830,743  |  fully-empty rows: 288,602
- Exact duplicate rows (within files, all columns): 203
- Header consistent across files: True
- Distinct content rows (identity ignored) shared across files: 33,548

## Label totals (raw strings, repr)

| label | rows |
|---|---:|
| 'BENIGN' | 2,273,097 |
| 'DoS Hulk' | 231,073 |
| 'PortScan' | 158,930 |
| 'DDoS' | 128,027 |
| 'DoS GoldenEye' | 10,293 |
| 'FTP-Patator' | 7,938 |
| 'SSH-Patator' | 5,897 |
| 'DoS slowloris' | 5,796 |
| 'DoS Slowhttptest' | 5,499 |
| 'Bot' | 1,966 |
| 'Web Attack – Brute Force' | 1,507 |
| 'Web Attack – XSS' | 652 |
| 'Infiltration' | 36 |
| 'Web Attack – Sql Injection' | 21 |
| 'Heartbleed' | 11 |

## Per file

| file | enc | rows | empty | dup(all) | dup(feat+label) | conflicting-label rows | src IPs | dst IPs |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv | utf-8-sig | 225,745 | 0 | 2 | 2,633 | 0 | 2067 | 2554 |
| Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv | utf-8-sig | 286,467 | 0 | 1 | 72,353 | 0 | 3667 | 4401 |
| Friday-WorkingHours-Morning.pcap_ISCX.csv | utf-8-sig | 191,033 | 0 | 2 | 6,888 | 0 | 4464 | 5348 |
| Monday-WorkingHours.pcap_ISCX.csv | utf-8-sig | 529,918 | 0 | 34 | 26,816 | 0 | 8239 | 9698 |
| Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv | utf-8-sig | 288,602 | 0 | 142 | 35,630 | 0 | 5101 | 6054 |
| Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv | cp1252 | 170,366 | 288,602 | 1 | 6,066 | 0 | 4203 | 5214 |
| Tuesday-WorkingHours.pcap_ISCX.csv | utf-8-sig | 445,909 | 0 | 4 | 24,065 | 0 | 7192 | 8490 |
| Wednesday-workingHours.pcap_ISCX.csv | utf-8-sig | 692,703 | 0 | 17 | 81,909 | 1091 | 7689 | 9012 |

### Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv

- Columns: 85; whitespace-padded headers: 70; duplicate names after strip: ['Fwd Header Length']
- Identity columns present: ['Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Timestamp']; missing: []
- Encoding: utf-8-sig; failed attempts: none
- Labels with non-ASCII chars: {}; containing U+FFFD: none
- Constant columns: ['Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'CWE Flag Count', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate']
- NaN/inf/non-numeric: {'Flow Bytes/s': {'nan': 4, '+inf': 30}, 'Flow Packets/s': {'+inf': 34}}
- Columns with negative values (count): {'Flow Duration': 2, 'Flow Bytes/s': 2, 'Flow Packets/s': 2, 'Flow IAT Mean': 2, 'Flow IAT Max': 2, 'Flow IAT Min': 108, 'Fwd IAT Min': 6, 'Init_Win_bytes_forward': 32925, 'Init_Win_bytes_backward': 88299}
- Timestamp shapes: {'9/9/9999 9:99': 225745}
- Timestamp date parts: {'7/7/2017': 225745}
- Timestamp hour histogram: {3: 52500, 4: 171693, 5: 1552}
- First/last: ['7/7/2017 3:30', '7/7/2017 3:30', '7/7/2017 3:30'] … ['7/7/2017 5:02', '7/7/2017 5:02', '7/7/2017 5:02']
- Flow ID: 86,421 unique, 139,324 repeated rows

### Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv

- Columns: 85; whitespace-padded headers: 70; duplicate names after strip: ['Fwd Header Length']
- Identity columns present: ['Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Timestamp']; missing: []
- Encoding: utf-8-sig; failed attempts: none
- Labels with non-ASCII chars: {}; containing U+FFFD: none
- Constant columns: ['Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'CWE Flag Count', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate']
- NaN/inf/non-numeric: {'Flow Bytes/s': {'nan': 15, '+inf': 356}, 'Flow Packets/s': {'+inf': 371}}
- Columns with negative values (count): {'Flow Duration': 36, 'Flow Bytes/s': 36, 'Flow Packets/s': 36, 'Flow IAT Mean': 36, 'Flow IAT Max': 36, 'Flow IAT Min': 176, 'Init_Win_bytes_forward': 60210, 'Init_Win_bytes_backward': 76942}
- Timestamp shapes: {'9/9/9999 9:99': 286467}
- Timestamp date parts: {'7/7/2017': 286467}
- Timestamp hour histogram: {1: 43037, 2: 191591, 3: 51839}
- First/last: ['7/7/2017 1:00', '7/7/2017 1:00', '7/7/2017 1:00'] … ['7/7/2017 3:29', '7/7/2017 3:29', '7/7/2017 3:29']
- Flow ID: 229,683 unique, 56,784 repeated rows

### Friday-WorkingHours-Morning.pcap_ISCX.csv

- Columns: 85; whitespace-padded headers: 70; duplicate names after strip: ['Fwd Header Length']
- Identity columns present: ['Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Timestamp']; missing: []
- Encoding: utf-8-sig; failed attempts: none
- Labels with non-ASCII chars: {}; containing U+FFFD: none
- Constant columns: ['Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'CWE Flag Count', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate']
- NaN/inf/non-numeric: {'Flow Bytes/s': {'nan': 28, '+inf': 94}, 'Flow Packets/s': {'+inf': 122}}
- Columns with negative values (count): {'Flow Duration': 9, 'Flow Bytes/s': 8, 'Flow Packets/s': 9, 'Flow IAT Mean': 9, 'Flow IAT Max': 9, 'Flow IAT Min': 225, 'Init_Win_bytes_forward': 95834, 'Init_Win_bytes_backward': 118419}
- Timestamp shapes: {'9/9/9999 99:99': 141048, '9/9/9999 9:99': 49985}
- Timestamp date parts: {'7/7/2017': 191033}
- Timestamp hour histogram: {8: 2, 9: 49983, 10: 71574, 11: 55425, 12: 14049}
- First/last: ['7/7/2017 8:59', '7/7/2017 8:59', '7/7/2017 9:00'] … ['7/7/2017 12:59', '7/7/2017 12:59', '7/7/2017 12:59']
- Flow ID: 101,977 unique, 89,056 repeated rows

### Monday-WorkingHours.pcap_ISCX.csv

- Columns: 85; whitespace-padded headers: 70; duplicate names after strip: ['Fwd Header Length']
- Identity columns present: ['Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Timestamp']; missing: []
- Encoding: utf-8-sig; failed attempts: none
- Labels with non-ASCII chars: {}; containing U+FFFD: none
- Constant columns: ['Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'CWE Flag Count', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate']
- NaN/inf/non-numeric: {'Flow Bytes/s': {'nan': 64, '+inf': 373}, 'Flow Packets/s': {'+inf': 437}}
- Columns with negative values (count): {'Flow Duration': 15, 'Flow Bytes/s': 9, 'Flow Packets/s': 15, 'Flow IAT Mean': 15, 'Flow IAT Max': 15, 'Flow IAT Min': 512, 'Fwd Header Length': 23, 'Bwd Header Length': 17, 'Fwd Header Length.1': 23, 'Init_Win_bytes_forward': 224495, 'Init_Win_bytes_backward': 299094, 'min_seg_size_forward': 23}
- Timestamp shapes: {'99/99/9999 99:99:99': 529918}
- Timestamp date parts: {'03/07/2017': 529918}
- Timestamp hour histogram: {1: 57600, 2: 48567, 3: 48916, 4: 65875, 5: 1841, 8: 809, 9: 74418, 10: 85079, 11: 88872, 12: 57941}
- First/last: ['03/07/2017 08:55:58', '03/07/2017 08:55:58', '03/07/2017 08:55:58'] … ['03/07/2017 03:24:07', '03/07/2017 01:03:43', '03/07/2017 10:34:39']
- Flow ID: 249,213 unique, 280,705 repeated rows

### Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv

- Columns: 85; whitespace-padded headers: 70; duplicate names after strip: ['Fwd Header Length']
- Identity columns present: ['Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Timestamp']; missing: []
- Encoding: utf-8-sig; failed attempts: none
- Labels with non-ASCII chars: {}; containing U+FFFD: none
- Constant columns: ['Bwd PSH Flags', 'Bwd URG Flags', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate']
- NaN/inf/non-numeric: {'Flow Bytes/s': {'nan': 18, '+inf': 189}, 'Flow Packets/s': {'+inf': 207}}
- Columns with negative values (count): {'Flow Duration': 4, 'Flow Bytes/s': 4, 'Flow Packets/s': 4, 'Flow IAT Mean': 4, 'Flow IAT Max': 4, 'Flow IAT Min': 353, 'Init_Win_bytes_forward': 102433, 'Init_Win_bytes_backward': 164351}
- Timestamp shapes: {'9/9/9999 9:99': 288602}
- Timestamp date parts: {'6/7/2017': 288602}
- Timestamp hour histogram: {1: 50104, 2: 57695, 3: 129511, 4: 48825, 5: 2467}
- First/last: ['6/7/2017 1:00', '6/7/2017 1:00', '6/7/2017 1:00'] … ['6/7/2017 5:04', '6/7/2017 5:04', '6/7/2017 5:04']
- Flow ID: 183,044 unique, 105,558 repeated rows

### Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv

- Columns: 85; whitespace-padded headers: 70; duplicate names after strip: ['Fwd Header Length']
- Identity columns present: ['Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Timestamp']; missing: []
- Encoding: cp1252; failed attempts: [('utf-8-sig', 5003134, '96', '200,252,3,32,0,0,0,0,0,0,0,0,Web Attack \x96 Brute Force\r\n192.168.10.15-23.194.182.6')]
- Labels with non-ASCII chars: {'Web Attack – Brute Force': ['U+2013'], 'Web Attack – XSS': ['U+2013'], 'Web Attack – Sql Injection': ['U+2013']}; containing U+FFFD: none
- Constant columns: ['Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'CWE Flag Count', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate']
- NaN/inf/non-numeric: {'Flow Bytes/s': {'nan': 20, '+inf': 115}, 'Flow Packets/s': {'+inf': 135}}
- Columns with negative values (count): {'Flow Duration': 11, 'Flow Bytes/s': 10, 'Flow Packets/s': 11, 'Flow IAT Mean': 11, 'Flow IAT Max': 11, 'Flow IAT Min': 263, 'Init_Win_bytes_forward': 81911, 'Init_Win_bytes_backward': 102373}
- Timestamp shapes: {'9/9/9999 99:99': 108042, '9/9/9999 9:99': 62324}
- Timestamp date parts: {'6/7/2017': 170366}
- Timestamp hour histogram: {8: 6, 9: 62318, 10: 45814, 11: 42676, 12: 19552}
- First/last: ['6/7/2017 8:59', '6/7/2017 8:59', '6/7/2017 8:59'] … ['6/7/2017 12:59', '6/7/2017 12:59', '6/7/2017 12:59']
- Flow ID: 89,866 unique, 80,500 repeated rows

### Tuesday-WorkingHours.pcap_ISCX.csv

- Columns: 85; whitespace-padded headers: 70; duplicate names after strip: ['Fwd Header Length']
- Identity columns present: ['Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Timestamp']; missing: []
- Encoding: utf-8-sig; failed attempts: none
- Labels with non-ASCII chars: {}; containing U+FFFD: none
- Constant columns: ['Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'CWE Flag Count', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate']
- NaN/inf/non-numeric: {'Flow Bytes/s': {'nan': 201, '+inf': 63}, 'Flow Packets/s': {'+inf': 264}}
- Columns with negative values (count): {'Flow Duration': 17, 'Flow Packets/s': 17, 'Flow IAT Mean': 17, 'Flow IAT Max': 17, 'Flow IAT Min': 505, 'Fwd Header Length': 11, 'Bwd Header Length': 5, 'Fwd Header Length.1': 11, 'Init_Win_bytes_forward': 200128, 'Init_Win_bytes_backward': 256599, 'min_seg_size_forward': 11}
- Timestamp shapes: {'9/9/9999 9:99': 312143, '9/9/9999 99:99': 133766}
- Timestamp date parts: {'4/7/2017': 445909}
- Timestamp hour histogram: {1: 36801, 2: 72649, 3: 48144, 4: 63007, 5: 165, 8: 1683, 9: 89694, 10: 58516, 11: 57171, 12: 18079}
- First/last: ['4/7/2017 8:54', '4/7/2017 8:54', '4/7/2017 8:54'] … ['4/7/2017 9:11', '4/7/2017 12:48', '4/7/2017 10:38']
- Flow ID: 211,628 unique, 234,281 repeated rows

### Wednesday-workingHours.pcap_ISCX.csv

- Columns: 85; whitespace-padded headers: 70; duplicate names after strip: ['Fwd Header Length']
- Identity columns present: ['Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Timestamp']; missing: []
- Encoding: utf-8-sig; failed attempts: none
- Labels with non-ASCII chars: {}; containing U+FFFD: none
- Constant columns: ['Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'CWE Flag Count', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate']
- NaN/inf/non-numeric: {'Flow Bytes/s': {'nan': 1008, '+inf': 289}, 'Flow Packets/s': {'+inf': 1297}}
- Columns with negative values (count): {'Flow Duration': 21, 'Flow Bytes/s': 16, 'Flow Packets/s': 21, 'Flow IAT Mean': 21, 'Flow IAT Max': 21, 'Flow IAT Min': 749, 'Fwd IAT Min': 11, 'Fwd Header Length': 1, 'Fwd Header Length.1': 1, 'Init_Win_bytes_forward': 203253, 'Init_Win_bytes_backward': 335475, 'min_seg_size_forward': 1}
- Timestamp shapes: {'9/9/9999 99:99': 396955, '9/9/9999 9:99': 295748}
- Timestamp date parts: {'5/7/2017': 692703}
- Timestamp hour histogram: {1: 48902, 2: 63868, 3: 66142, 4: 44878, 5: 3547, 8: 14107, 9: 54304, 10: 301876, 11: 71086, 12: 23993}
- First/last: ['5/7/2017 8:42', '5/7/2017 8:42', '5/7/2017 8:42'] … ['5/7/2017 10:06', '5/7/2017 1:19', '5/7/2017 2:43']
- Flow ID: 226,768 unique, 465,935 repeated rows
