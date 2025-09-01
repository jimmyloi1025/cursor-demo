                    +-----------------+
                    |  SIEM System    |
                    | (Splunk/QRadar) |
                    +--------+--------+
                             ▲
                             │
                    +--------+--------+
                    |  Alert Manager  |
                    +--------+--------+
                             ▲
                             │
                    +--------+--------+
                    | Network Monitor |
                    | (Cursor Demo)   |
                    +--------+--------+
                             ▲
                             │
+---------------+  +--------+--------+  +---------------+
| Cloud Sensors |  | On-Prem Sensors |  | IoT Devices   |
| (AWS/Azure)   |  | (Firewalls)     |  | (Security Cams)|
+---------------+  +-----------------+  +---------------+