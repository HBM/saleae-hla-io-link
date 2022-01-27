# SPDX-License-Identifier: MIT
#
# The MIT License (MIT)
#
# Copyright (c) <2021> Hottinger Brüel & Kjaer GmbH, Im Tiefen See 45, 64293 Darmstadt, Germany
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# IO Link Frame Classes
# For more information and documentation, please go to https://io-link.com/en/index.php

from saleae.analyzers import AnalyzerFrame


chksum = (0x2d, 0x3c, 0x0c, 0x1d, 0x3f, 0x2e, 0x1e, 0x0f,
          0x0f, 0x1e, 0x2e, 0x3f, 0x1d, 0x0c, 0x3c, 0x2d,
          0x39, 0x28, 0x18, 0x09, 0x2b, 0x3a, 0x0a, 0x1b,
          0x1b, 0x0a, 0x3a, 0x2b, 0x09, 0x18, 0x28, 0x39,
          0x09, 0x18, 0x28, 0x39, 0x1b, 0x0a, 0x3a, 0x2b,
          0x2b, 0x3a, 0x0a, 0x1b, 0x39, 0x28, 0x18, 0x09,
          0x1d, 0x0c, 0x3c, 0x2d, 0x0f, 0x1e, 0x2e, 0x3f,
          0x3f, 0x2e, 0x1e, 0x0f, 0x2d, 0x3c, 0x0c, 0x1d,
          0x35, 0x24, 0x14, 0x05, 0x27, 0x36, 0x06, 0x17,
          0x17, 0x06, 0x36, 0x27, 0x05, 0x14, 0x24, 0x35,
          0x21, 0x30, 0x00, 0x11, 0x33, 0x22, 0x12, 0x03,
          0x03, 0x12, 0x22, 0x33, 0x11, 0x00, 0x30, 0x21,
          0x11, 0x00, 0x30, 0x21, 0x03, 0x12, 0x22, 0x33,
          0x33, 0x22, 0x12, 0x03, 0x21, 0x30, 0x00, 0x11,
          0x05, 0x14, 0x24, 0x35, 0x17, 0x06, 0x36, 0x27,
          0x27, 0x36, 0x06, 0x17, 0x35, 0x24, 0x14, 0x05,
          0x05, 0x14, 0x24, 0x35, 0x17, 0x06, 0x36, 0x27,
          0x27, 0x36, 0x06, 0x17, 0x35, 0x24, 0x14, 0x05,
          0x11, 0x00, 0x30, 0x21, 0x03, 0x12, 0x22, 0x33,
          0x33, 0x22, 0x12, 0x03, 0x21, 0x30, 0x00, 0x11,
          0x21, 0x30, 0x00, 0x11, 0x33, 0x22, 0x12, 0x03,
          0x03, 0x12, 0x22, 0x33, 0x11, 0x00, 0x30, 0x21,
          0x35, 0x24, 0x14, 0x05, 0x27, 0x36, 0x06, 0x17,
          0x17, 0x06, 0x36, 0x27, 0x05, 0x14, 0x24, 0x35,
          0x1d, 0x0c, 0x3c, 0x2d, 0x0f, 0x1e, 0x2e, 0x3f,
          0x3f, 0x2e, 0x1e, 0x0f, 0x2d, 0x3c, 0x0c, 0x1d,
          0x09, 0x18, 0x28, 0x39, 0x1b, 0x0a, 0x3a, 0x2b,
          0x2b, 0x3a, 0x0a, 0x1b, 0x39, 0x28, 0x18, 0x09,
          0x39, 0x28, 0x18, 0x09, 0x2b, 0x3a, 0x0a, 0x1b,
          0x1b, 0x0a, 0x3a, 0x2b, 0x09, 0x18, 0x28, 0x39,
          0x2d, 0x3c, 0x0c, 0x1d, 0x3f, 0x2e, 0x1e, 0x0f,
          0x0f, 0x1e, 0x2e, 0x3f, 0x1d, 0x0c, 0x3c, 0x2d)


class IOLinkFrame(AnalyzerFrame):

    def __init__(self, type, framelength, first_frame, second_frame):
        data = first_frame.data["data"][0]
        super().__init__(type, first_frame.start_time, second_frame.end_time, {
            'Direction': ('Write', 'Read')[(data & 0x80) != 0],
            'Addr': bytes([data & 0x1F]),
            'Channel': ('Process', 'Page', 'Diagnosis', 'ISDU')[(data >> 5) & 3]})
        self.numOfBytes = 2
        self.frameLength = framelength
        data2 = second_frame.data["data"][0]
        self.cktacc = data ^ (data2 & 0xC0)
        self.cksacc = 0
        self.cktksum = data2 & 0x3F

    def append(self, frame):
        self.numOfBytes = self.numOfBytes + 1
        self.end_time = frame.end_time
        if self.numOfBytes >= self.frameLength:
            data = frame.data["data"][0]
            self.data["valid"] = (data & 0x40) == 0
            self.data["event"] = (data & 0x80) != 0
            self.cksacc ^= (data & 0xC0)
            ckssum = data & 0x3F
            if (self.cktksum != chksum[self.cktacc]) and (ckssum != chksum[self.cksacc]):
                self.data["error"] = "CKT, CKS"
            elif chksum[self.cktacc] != self.cktksum:
                self.data["error"] = "CKT"
            elif chksum[self.cksacc] != ckssum:
                self.data["error"] = "CKS"
            return self

    def printframe(self):
        addr = self.data["Addr"][0]
        print(self.data["direction"] + " Pageaddress " + hex(addr) + " ("+ str(addr) + "d)")


class IOLinkFrameType0(IOLinkFrame):

    def __init__(self, first_frame, second_frame):
        super().__init__("Type_0", 4, first_frame, second_frame)

    def append(self, frame):
        data = frame.data["data"][0]
        if self.numOfBytes == 2:
            self.data["OD"] = "0x{:02x}".format(data)
            if self.data['Direction'] == 'Write':
                self.cktacc ^= data
            else:
                self.cksacc ^= data
        return super().append(frame)

    def printframe(self):
        addr = self.data["Addr"][0]
        print(self.data["Direction"] + " Pageaddress " + hex(addr) + " ("+ str(addr) + "d) Value: " + self.data["OD"][:4])


class IOLinkFrameType1(IOLinkFrame):

    def __init__(self, name, len, first_frame, second_frame):
        super().__init__(name, sum(len) + 3, first_frame, second_frame)
        self.pd_len = len[0]
        self.od_len = len[1]
        self.key = ("OD", "PD")[self.pd_len > 0]

    def append(self, frame):
        if self.numOfBytes < self.frameLength - 1:
            data = frame.data["data"][0]
            if self.data['Direction'] == 'Write':
                self.cktacc ^= data
            else:
                self.cksacc ^= data
            self.data[self.key] = self.data.get(self.key, '0x') + "{:02x}".format(data)
        return super().append(frame)

    def printframe(self):
        addr = self.data["Addr"][0]
        print(self.data["Direction"] + " Pageaddress " + hex(addr) + " ("+ str(addr) + "d) Value: " + self.data[self.key][:4])


class IOLinkFrameType2(IOLinkFrame):

    def __init__(self, name, len, first_frame, second_frame):
        super().__init__(name, sum(len) + 3, first_frame, second_frame)
        self.pdin_len = len[2]
        self.pdout_len = len[0]
        self.od_len = len[1]

    def append(self, frame):
        data = frame.data["data"][0]
        if self.numOfBytes < (2 + self.pdout_len):
            self.cktacc ^= data
            self.data['PDout'] = self.data.get('PDout', '0x') + "{:02x}".format(data)
        elif self.numOfBytes < (2 + self.pdout_len + self.od_len):
            if self.data['Direction'] == 'Write':
                self.cktacc ^= data
            else:
                self.cksacc ^= data
            self.data['OD'] = self.data.get('OD', '0x') + "{:02x}".format(data)
        elif self.numOfBytes < (2 + self.pdout_len + self.od_len + self.pdin_len):
            self.data['PDin'] = self.data.get('PDin', '0x') + "{:02x}".format(data)
            self.cksacc ^= data

        return super().append(frame)

    def printframe(self):
        addr = self.data["Addr"][0]
        print(self.data["Direction"] + " Pageaddress " + hex(addr) + " ("+ str(addr) + "d) Value: " + self.data["OD"][:4])


class IOLinkFrameType3(IOLinkFrame):

    def __init__(self, first_frame, second_frame):
        super().__init__("Type_3", 2, first_frame, second_frame)
        self.data["error"] = "RESERVED TYPE"
