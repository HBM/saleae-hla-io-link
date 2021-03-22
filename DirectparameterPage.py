# IO Link Direct Parameter Page 1
# For more information and documentation, please go to https://io-link.com/en/index.php

from saleae.analyzers import AnalyzerFrame

directparameterPage1 = ('MasterCommand',
                        'MasterCycleTime',
                        'MinCycleTime',
                        'M-sequence Capability',
                        'RevisionID',
                        'ProcessDataIn',
                        'ProcessDataOut',
                        'VendorID1 (MSB)',
                        'VendorID2 (LSB)',
                        'DeviceID1 (MSB)',
                        'DeviceID2 (  B)',
                        'DeviceID3 (LSB)',
                        'FunctionID1 (MSB)',
                        'FunctionID2 (LSB)',
                        'reserved',
                        'SystemCommand')

masterCommand = {
    0x5A: 'Fallback',
    0x95: 'MasterIdent',
    0x96: 'DeviceIdent',
    0x97: 'DeviceStartup',
    0x98: 'ProcessDataOutputOperate',
    0x99: 'DeviceOperate',
    0x9A: 'DevicePreoperate',
}

systemCommand = {
    0x01: 'ParamUploadStart',
    0x02: 'ParamUploadEnd',
    0x03: 'ParamDownloadStart',
    0x04: 'ParamDownloadEnd',
    0x05: 'ParamDownloadStore',
    0x06: 'ParamBreak',
    0x80: 'Device reset',
    0x81: 'Application reset',
    0x82: 'Restore factory settings',
}


def printDPP2(frame: AnalyzerFrame):
    addr = frame.data['Addr'][0] & 0xf
    if frame.data['Direction'] == 'Write':
        print("DirectParameter Page2 WRITE to  Addr: " + hex(addr) + " value: " + frame.data['OD'][:4])
    else:
        print("DirectParameter Page2 READ from Addr: " + hex(addr) + " value: " + frame.data['OD'][:4])


def printMasterCommand(frame: AnalyzerFrame):
    val = int(frame.data['OD'][:4] ,0)
    print("MasterCommand: " + hex(val) + " (" + masterCommand[val] + ")")


def printSystemCommand(frame: AnalyzerFrame):
    val = int(frame.data['OD'][:4] ,0)
    print("SystemCommand: " + hex(val) + " (" + systemCommand[val] + ")")


def printDPP1(frame: AnalyzerFrame):
    addr = frame.data['Addr'][0] & 0xf
    if addr == 0 and frame.data['Direction'] == 'Write':
        return printMasterCommand(frame)
    if addr == 15 and frame.data['Direction'] == 'Write':
        return printSystemCommand(frame)

    if frame.data['Direction'] == 'Write':
        print("DirectParameter Page1 WRITE to  Addr: " + hex(addr) + " (" + directparameterPage1[addr] + ") value: " +
              frame.data['OD'][:4])
    else:
        print("DirectParameter Page1 READ from Addr: " + hex(addr) + " (" + directparameterPage1[addr] + ") value: " +
              frame.data['OD'][:4])


def printFrame(frame: AnalyzerFrame):
    if frame.data['Addr'][0] > 15:
        printDPP2(frame)
    else:
        printDPP1(frame)
