
 # Saleae IO-Link Extension
  
This is a HighLevelAnalyzer for [IO-Link](https://io-link.com/en/) communication and the Saleae Logic 2 Software. General information on HighLevelAnalyzers can be found at [Saleae](https://support.saleae.com/extensions).
  
## Usage
1. Add the analyzer to Logic 2 from the extension window.
2. Capture or load up a capture of IO-Link traffic. You need to capture the C/Q line (24V) directly. You cannot capture TX and RX independently between Transceiver and your uC.
3. Add an "Async Serial" Analyzer with "Even Parity", "One Stop Bit", "LSB first", "Signal Inversion", and the Baudrate of your IO-Link device.
   - COM1 =   4800
   - COM2 =  38400
   - COM3 = 230400
4. Add the "IO Link" Analyzer with the "Async Serial" analyzer as source. Set the M-Sequence types for Type\_1 and Type\_2 frames. When Type\_2\_V is selected, you need to specifiy the Byte length of PDin, PDout, and OD. If you don't know the capabilities of your device, try to capture the reading of the "M-Sequency Capabilities" field from DirectParameter Page 1 during the Startup Phase and look up the corresponding lengths in the IO-Link specification.

## Examples
The "examples" folder contains a IO-Link capture with the settings "Type\_1\_V (8 OD)", "Type\_2\_V", "PDout length" = 0, "PDin length" = 4, "OD length" = 2.

![Example](https://github.com/HBM/saleae-hla-io-link/raw/main/examples/demo.png)

## Changelog
### v1.1.0
- Combine UART frames into IO-Link frames in adherence to the timing requirements of the IO-Link specification
- minor changes

### v1.0.0
- Initial version

## Features
- Support of all M-Sequence types
- Parsing of all frame fields
- Checksum tests for CKS and CKT
- DirectParameterPage accesses printed to console
- Parsing of predefined MasterCommands and SystemCommands

## Non-Features
Things that are (currently) not supported:
- Interleaved mode
- Parsing of ISDU requests
- Anything else I didn't think of...

