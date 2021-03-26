# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
import IOLinkFrame
import DirectparameterPage

type1_frames = {
    #          (pd, od)
    'Type_1_1': (2, 0),
    'Type_1_2': (0, 2),
    'Type_1_V (8 OD)': (0, 8),
    'Type_1_V (32 OD)': (0, 32),
}

type2_frames = {
    #      (pdout, od, pdin)
    'Type_2_1': (0, 1, 1),
    'Type_2_2': (0, 1, 2),
    'Type_2_3': (1, 1, 0),
    'Type_2_4': (2, 1, 0),
    'Type_2_5': (1, 1, 1),
    'Type_2_6': (2, 1, 2),
    'Type_2_V': (0, 0, 0),
}


# High level analyzers must subclass the HighLevelAnalyzer class.
class IOLinkAnalyzer(HighLevelAnalyzer):
    # List of settings that a user can set for this High Level Analyzer.
    type1_frame = ChoicesSetting(label = 'Type_1', choices = type1_frames.keys())
    type2_frame = ChoicesSetting(label = 'Type_2', choices = type2_frames.keys())
    pdout_len = NumberSetting(label='PDout length (only with Type_2_V)', min_value=0.0, max_value=32.0)
    od_len = NumberSetting(label='OD length (only with Type_2_V)', min_value=0.0, max_value=32.0)
    pdin_len = NumberSetting(label='PDin length (only with Type_2_V)', min_value=0.0, max_value=32.0)

    # An optional list of types this analyzer produces, providing a way to customize the way frames are displayed in Logic 2.
    result_types = {
        'Type_0': {
            'format': '{{data.Direction}} {{data.Channel}} {{data.Addr}} OD: {{data.OD}}'
        },
        'Type_1_1': {
            'format': '{{data.Direction}} {{data.Channel}} {{data.Addr}} PD: {{data.PD}}'
        },
        'Type_1_2': {
            'format': '{{data.Direction}} {{data.Channel}} {{data.Addr}} OD: {{data.OD}}'
        },
        'Type_1_V': {
            'format': '{{data.Direction}} {{data.Channel}} {{data.Addr}} OD: {{data.OD}}'
        },
        'Type_2_1': {
            'format': '{{data.Direction}} {{data.Channel}} {{data.Addr}} OD: {{data.OD}} PDin: {{data.PDin}}'
        },
        'Type_2_2': {
            'format': '{{data.Direction}} {{data.Channel}} {{data.Addr}} OD: {{data.OD}} PDin: {{data.PDin}}'
        },
        'Type_2_3': {
            'format': '{{data.Direction}} {{data.Channel}} {{data.Addr}} PDout: {{data.PDout}} OD: {{data.OD}}'
        },
        'Type_2_4': {
            'format': '{{data.Direction}} {{data.Channel}} {{data.Addr}} PDout: {{data.PDout}} OD: {{data.OD}}'
        },
        'Type_2_5': {
            'format': '{{data.Direction}} {{data.Channel}} {{data.Addr}} PDout: {{data.PDout}} OD: {{data.OD}} PDin: {{data.PDin}}'
        },
        'Type_2_6': {
            'format': '{{data.Direction}} {{data.Channel}} {{data.Addr}} PDout: {{data.PDout}} OD: {{data.OD}} PDin: {{data.PDin}}'
        },
    }

    def __init__(self):
        self.process = self.parseByte()
        self.process.send(None)
        str = '{{data.Direction}} {{data.Channel}} {{data.Addr}}'
        if self.pdout_len > 0:
            str = str + ' PDout: {{data.PDout}}'
        if self.od_len > 0:
            str = str + ' OD: {{data.OD}}'
        if self.pdin_len > 0:
            str = str + ' PDin: {{data.PDin}}'
        self.result_types['Type_2_V'] = {'format': str}
        type2_frames['Type_2_V'] = (self.pdout_len, self.od_len, self.pdin_len)

    def initFrame(self, frame0, frame1):
        frametype = frame1.data["data"][0] >> 6
        if frametype == 0:
            return IOLinkFrame.IOLinkFrameType0(frame0, frame1)
        if frametype == 1:
            len = type1_frames[self.type1_frame]
            return IOLinkFrame.IOLinkFrameType1(self.type1_frame[:8], len, frame0, frame1)
        if frametype == 2:
            len = type2_frames[self.type2_frame]
            return IOLinkFrame.IOLinkFrameType2(self.type2_frame, len, frame0, frame1)
        return None

    def parseByte(self):
        frame: AnalyzerFrame = yield None
        while True:
            pendingFrame = self.initFrame(frame, (yield None))
            ret: AnalyzerFrame = None
            while ret is None:
                ret = pendingFrame.append((yield None))
            frame = yield ret

    def decode(self, frame: AnalyzerFrame):
        if frame.type != 'data':
            return

        if "error" in frame.data:
            return

        ret = self.process.send(frame)
        if ret is not None and ret.data['Channel'] == 'Page':
            DirectparameterPage.printFrame(ret)
        return ret