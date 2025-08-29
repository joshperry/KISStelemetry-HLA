from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting

def crc8_kiss(data: bytes) -> int:
    polynomial = 0x07
    crc = 0x00
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 0x80:
                crc = (crc << 1) ^ polynomial
            else:
                crc <<= 1
            crc &= 0xFF  # Ensure CRC remains 8-bit
    return crc

class KissTelemetryHla(HighLevelAnalyzer):
    '''
     BLHeli32 / KISS Telemetry Protocol

         - Serial protocol is 115200,8N1
         - Big-Endian byte order

     Data Frame Format
     ―――――――――――――――――――――――――――――――――――――――――――――――
         0:       Temperature
       1,2:       Voltage in 10mV
       3,4:       Current in 10mA
       5,6:       Consumption mAh
       7,8:       RPM in 100rpm steps
         9:       CRC8
    '''
    candidate_frames = []

    result_types = {
        'temperature': {
            'format': '{{data.temperature}}'
        },
        'voltage': {
            'format': '{{data.voltage}}mV'
        },
        'current': {
            'format': '{{data.current}}mA'
        },
        'consumption': {
            'format': '{{data.consumption}}mAh'
        },
        'rpm': {
            'format': '{{data.rpm}}eRPM'
        },
        'checksum': {
            'format': '{{data.crcresult}}'
        },
        'badframes': {
            'format': 'bad'
        }
    }

    def __init__(self):
        '''
        Initialize HLA.
        '''

    def decode(self, frame: AnalyzerFrame):
        '''
        Watch a sliding window of 10 frames for a good checksum to synchronize.
        '''
        self.candidate_frames.append(frame)

        # See if we've gotten enough frames yet
        if len(self.candidate_frames) < 10:
            return

        # See if the last 10 frames have a good checksum
        crcframe = self.candidate_frames[-1]
        crc = crcframe.data['data'][0]
        testframes = self.candidate_frames[-10:-1]
        framedata = bytes().join([frame.data['data'] for frame in testframes])
        if crc8_kiss(framedata) != crc:
            return

        # Output bad frames if any
        baframes = []
        if len(self.candidate_frames) > 10:
            badframes = self.candidate_frames[:-10]
            baframes.append(AnalyzerFrame('badframes', badframes[0].start_time, badframes[-1].end_time))

        # List of good analyzer frames to put out
        aframes = [
            AnalyzerFrame('temperature', testframes[0].start_time, testframes[0].end_time, { 'temperature': framedata[0] }),
            AnalyzerFrame('voltage', testframes[1].start_time, testframes[2].end_time, { 'voltage': int.from_bytes(framedata[1:3], 'big')*10 }),
            AnalyzerFrame('current', testframes[3].start_time, testframes[4].end_time, { 'current': int.from_bytes(framedata[3:5], 'big')*10 }),
            AnalyzerFrame('consumption', testframes[5].start_time, testframes[6].end_time, { 'consumption': int.from_bytes(framedata[5:7], 'big')*10 }),
            AnalyzerFrame('rpm', testframes[7].start_time, testframes[8].end_time, { 'rpm': int.from_bytes(framedata[7:9], 'big')*10 }),
            AnalyzerFrame('checksum', crcframe.start_time, crcframe.end_time, { 'crcresult': 'good' })
        ]

        # Clear candidate buffer
        self.candidate_frames = []

        return baframes + aframes
