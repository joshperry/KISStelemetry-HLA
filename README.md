# BLHeli32/KISS ESC Telemetry HLA

Saleae Logic 2 High Level Analyzer: Telemetry sent by ESCs that use the KISS protocol like BLHeli32.

## Getting Started

Usually this telemetry is carried over an Async Serial connection at 115200 8n1, so add one of those.
Then add this HLA and set the serial connection analyzer as its input.

## Features

Shows the following info in the telemetry packets after checking the CRC:
- Temperature in C
- Voltage in mV
- Current in mA
- Consumption in mAh
- eRPM

Any frames that can't be verified with a CRC are shown as "bad".
