# RMII guide
This guide exists because information on how to structure MII/RMII data is hard to come by. It is also not helpful that asking an AI that is also provided datasheets with accurate information on the subject will return garbage information. Thus the need to document this so that X person can deterministically find this info.


## RMII Overview

RMII (Reduced Media Independent Interface) reduces MII's 16 data/control pins down to 7-8 pins, simplifying PCB layout and reducing trace count between MAC and PHY.

| Signal | Direction (PHY perspective) | Function |
|--------|----------------------------|----------|
| **TX_EN** | Input | Transmit enable - MAC asserts when presenting valid dibits |
| **TXD[1:0]** | Input | Transmit data - 2-bit dibit per clock cycle |
| **CRS_DV** | Output | Carrier Sense / Receive Data Valid (combined signal) |
| **RXD[1:0]** | Output | Receive data - 2-bit dibit per clock cycle |
| **RX_ER** | Output | Receive error indicator (optional on some PHYs) |
| **REF_CLK** | Input or Output | 50 MHz reference clock (direction depends on mode) |

RMII signals that require sync are synchronous to the 50 MHz REF_CLK **rising edge.** PHY updates RXD[1:0], CRS_DV, RX_ER shortly after the rising edge. MAC should sample on the next rising edge (capturing the previous cycle's value)


## REF_CLK: Reference Clock

All RMII signals are synchronous to a continuous 50 MHz reference clock. Two modes exist:

### Clock Source Mode (PHY is clock source)
- PHY takes 25 MHz crystal/oscillator on XI/XO pins
- PHY PLL multiplies to 50 MHz internally
- PHY outputs 50 MHz on REF_CLK pin to MAC
- Example: KSZ8081RNA default, LAN8720A with nINTSEL pin low at reset

### Clock Follower Mode (MAC is clock source)
- External 50 MHz oscillator feeds both PHY (XI pin) and MAC
- PHY REF_CLK pin left unconnected or used as input
- Example: DP83826 RMII follower mode

**Clock Requirements** (typical):
- Frequency: 50 MHz ±50 ppm
- Duty cycle: 40-60%
- Jitter: <150 ps peak-to-peak


## Tx0/Tx1/TxEN and CLKREF/RETCLK interface

### Frame Transmission Sequence
First 8 bytes in transmission are preamble and start of frame delimiter (SFD).
The preamble is composed of 7 bytes, all dibits valued `0b01`, so TX0=1, TX1=0.
The SFD is composed of 3 `0b01` dibits and a `0b11` dibit where both TX0 and TX1 are high for a single CLKREF cycle. After the final SFD(`0b11`) dibit the frame data is presented of the wire.

TX_EN is asserted synchronously with the first dibit of preamble and remains HIGH throughout the entire frame (preamble, SFD, payload, CRC). 

Example at 100M link mode:
```
REF_CLK:   _|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_ ...
TX_EN:     __|‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾  ... (HIGH until end of frame)
TX0:       __|‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾...‾‾‾‾‾‾‾‾‾‾‾‾|.D|.T| ...
TX1:       _______________________________...________|‾‾‾|.A|.A| ...
TXD[1:0]:  00|01 |01 |01 |01 |...|01 |01 |01 |01 |01 |11 |DA|TA| ...
              └── Preamble (28 dibits)──┘└SFD (4 dibits)┘└─ Frame data ─...
```


**Inter-Packet Gap (IPG)**: After TX_EN deasserts, TXD[1:0] must be held at 00 for a minimum of 96 bit times (48 dibits = 12 bytes at 100M). This is the minimum gap required between consecutive frame transmissions.

```
End of frame with IPG at 100M link mode:

REF_CLK:   _|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_ ...
TX_EN:     ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾|_____________________________ ...
TXD[1:0]:  ...data...|CR|C |00|00|00|00|00|00|00|00|...
                      └CRC┘ └──── IPG (≥48 dibits) ────...
```

### Practical Tx example:
To illustrate programatically we'll suppose we have a hardware which requires a byte for every clock. Each byte contains 3 bits to be sent out: Tx0,Tx1,TxEn bits.
This is not a contrived example, it is how Sandeep Mistry's and Rob Scott's LAN8720 drivers work.
```c
uint8_t tx0 = 1<<0;
uint8_t tx1 = 1<<1;
uint8_t txen = 1<<3;
uint8_t txdmsk = tx0|tx1; // data mask.

// wait for previous transmission to end to comply with RMII.
transmit_wait()

// 28 dibits of preamble. "TXEN is asserted synchronously with first dibit of the preamble" -KSZ8081RNA/RND datasheet. 7 bytes of preamble.
int index = 0;
for (int i = 0; i < 28; i++) {
  tx_frame_bits[index++] = txen | tx0; // 0b101 == 0x5
}

// Start Frame Delimiter marks end of preamble. 
// First 3 bytes written identical to loop above,
// we just make the strict distinction of preamble vs. SFD
tx_frame_bits[index++] = tx0|txen; // 0b101 == 0x5
tx_frame_bits[index++] = tx0|txen; // 0b101 == 0x5
tx_frame_bits[index++] = tx0|txen; // 0b101 == 0x5
tx_frame_bits[index++] = tx0|tx1|txen; // 0b111 == 0x7

// Now store the actual ethernet frame bits. We assume the CRC is included in length.
for (int i = 0; i < frame_len; i++) {
  uint8_t b = tx_frame[i]; // The actual frame data.

  tx_frame_bits[index++] = txen | ((b >> 0) & txdmsk);
  tx_frame_bits[index++] = txen | ((b >> 2) & txdmsk);
  tx_frame_bits[index++] = txen | ((b >> 4) & txdmsk);
  tx_frame_bits[index++] = txen | ((b >> 6) & txdmsk);
}

// TxEnable driven low. This ensures sending hardware is acquired 
// during the TxEnable low period which has a minimum time must remain low between transmissions.
// "TXD[1:0] is 00 to indicate idle when TXEN is deasserted. The PHY ignores values other than 00 on TXD[1:0] while TXEN is deasserted" -KSZ8081RNA/RND
for (int i = 0; i < (12 * 4); i++) {
  tx_frame_bits[index++] = 0x00;
}
// transmit enacts tx0,tx1,txen bits over wire. Need not be blocking since we call transmit_wait.
transmit(tx_frame_bits, index)
```

## Practical Tx example: RobScott external clock driven PIO Tx
Below is tx PIO program for external clock driven transmit. This example can run with a PHY with a output RETCLK signal without modifying the breakout board, such as is the case with Sandeep's library. Notice the clock is an input on the WAIT instruction.
```c
// TX_[0,1,EN] are output and set pins.
// TX_EN is sideset pin.
// REFCLK (RETCLK) is in pin.

// This program runs at half a cycle per clock (1HC/clock) to handle 
// the data loop, so every delay needs to be doubled.
// Every PIO cycle can be thought of a single bit since we use RMII with dibit width.

// Begin waiting for data to transmit, TX_EN deasserted.
// In doing so we ensure we add at least a byte to IPG.
set  pins, 0b00  side 0 [5] // 6 Half-cycles
// wait for data to transmit here.
pull block       side 0     // 1 half cycle. etc. Here we wait for user provided data.
wait 1 pin, 0    side 0     // Synchronizes clock.

// Write 0b01 for 31 cycles, preamble start.
// 16+16+16+14=62HC=31 cycles
set  pins, 0b01  side 1 [15] // 16HC
nop              side 1 [15] // 16HC
nop              side 1 [15] // 16HC 
// Prepare for 10 IPG bytes. 
set x, 9         side 1 [13] // 14HC

// SFD: Write start-frame-delimiter 0b11 for 1 cycle (preamble+SFD finish)
set pins, 0b11   side 1 [1] // adds one cycle, making 32 cycles.

// main loop: Write the frame data, 2 bits at a time.
// 2 PIO cycles = 2 Half-cycles = 1 RMII clock period/cycle.
loop_t:
out pins, 2      side 1 // Shift in 2 bits over TX0,TX1
jmp !osre,loop_t   side 1

// Do IPG of 12 bytes with TX_EN deasserted: 
//  - 1 here at SET
//  - 10 in ipg loop at JMP.
//  - 1 at start SET/PULL/WAIT
set pins, 0      side 0 [7]
ipg_t:
jmp x--,ipg_t      side 0 [7] // 10 times, so 80HC here.
```

## Practical Tx example: Robscott self driven
```c
// Preamble+SFD is composed of 32 RMII cycles. Note: Each byte is 4 RMII cycles.
// Strictly speaking the Preamble is 28 cycles of TX0=1, TX1=0
// followed by the SFD which is 4 cycles, 3 of them TX0=1, TX1=0
// and one cycle with TX0=1, TX1=1.
// These dibits, when interpreted as bytes as per RMII are 7 bytes of 0x55 (Preamble) followed by a single 0x57 byte (SFD).

// Out pins are set as [TX0,TX1,TXEN].
// Assert TXEN=1 (a.k.a DV) and set TX0=1, TX1=0. We now need to emit 31 RMII cycles of this. 
// Following 6 instructions do 3 RMII cycles.
preamb_t:
set  pins,  0b101   side 0 // Set pins TX0=1, TX1=0, TXEN=1
// Shift 16 bits from OSR into x
out  x,  8 side 1 
in   x,  8 side 0 
out  x,  8 side 1
in   x, 24 side 0 
set  x, 27 side 1 // Set X=27, to loop 28 times in ploop_t
ploop_t:
set  y, 22         side 0 // Setup Y reg for IPG inner loop.
jmp  x--,ploop_t   side 1
// By now 3+28=31 RMII cycles complete with TX0=1,TX1=0.
set  pins, 0b111 side 0 // We need last cycle SFD with TX0=1,TX1=1,TXEN=1
mov  x,  isr side 1 // Read package length from input buffer.

// Transmit until packet count exhausted
xmit_t:
out  pins, 2     side 0 // Send two bits of tx data.
jmp  x--,xmit_t  side 1 // loop until x==0 (data exhausted).

// Do Inter Packet Gap(IPG) - 960ns, 48 RMII dibit clks.
// Delay 47 clocks here, then 1 clock for Tx queue status.
ipg_t:
set  pins, 0b000  side 0 // TX0/1/EN deasserted during IPG. RMII bus is said to be idle.
nop               side 1 
nop               side 0
jmp  y--, ipg_t   side 1 // Do 23 times, we set Y to 22 above.
nop               side 0
nop               side 1
public tx_start_t:
.wraptarget_t
mov  x, status        side 0 // Get Tx not empty status.
jmp  !x, preamb_t     side 1
.wrap_t
```


## Rx0/Rx1/CRS_DV Interface

The receive path uses RXD[1:0] for data and CRS_DV as a combined carrier sense and data valid signal.

### Key points
1. CRS_DV combines two functions into one signal. Is **not synchronous in all RMII revisions.**
  - **CRS (Carrier Sense)**: Asserted when receive medium is non-idle ("idle" defined in IEEE 802.3). CRS is asserted based on PHY operating mode.
  - Loss of carrier results results in deassertion of CRS_DV synchronous to REF_CLK. See [DP83848 PHY datasheet](https://www.ti.com/lit/an/snla076a/snla076a.pdf) for more info.
  - The data on RXD[1:0] is considered valid once CRS_DV is asserted but is asynchronous relative REF_CLK, so RXD[1:0] is 0b00 until proper receive signal decoding takes place.
  - CRS_DV may be toggled on the second dibit of the next nibble after deassertion if it has additional bits to present to MAC (RMII revision 1.2 spec)

2. **RXD[1:0]** transitions synchronously to REF_CLK.
  - RXD[1:0] is 0b00 to indicate idle when CRS_DV is deasserted and remains 0b00 on CRS_DV assertion until proper receive decoding takes place.
  - For every clock period in which CRS_DV is asserted, RXD[1:0] transfers two bits of recovered data
  - For a normal reception upon detecting SSD(start of stream delimiter) after CRS_DV assertion the PHY will drive preamble 0b01 followed by the SFD (start of frame delimiter). MAC/STA should capture data after the SFD.
3. RX_ER is synchronous to REF_CLK and asserted for one or more REF_CLK periods to indicate that an error was detected somewhere in the frame being transferred to PHY while CRS_DV asserted. If CRS_DV not asserted RX_ER is ignored. Although frames should be discarded if RX_ER is set, if RX_ER unable to be checked the MAC checking the CRC should surface the error. Below are some common causes for RX_ER assertion:
  - 4B/5B invalid code group (100BASE-TX)
  - Bad SSD (Start of Stream Delimiter)
  - Signal amplitude below squelch threshold
  - PHY receive FIFO overflow
  
4. Some PHYs provide **RX_DV** signal. RX_DV is asserted with first properly recovered data (preamble) or false carrier detection. It is deasserted following transfer of final di-bit of recovered data. A full duplex MAC may use this signal to avoid having to recover RX_DV from CRS_DV.


### Frame Reception Sequence
Example supposes 100M link mode:
```
REF_CLK:    |‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾| ...
CRS|CRS_DV: __|‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ ... (stays HIGH until end of frame)
DV:         __________|‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾ ...
RXD[1:0]:  00|00|00|00|01|01|01|01|01|01|01|01|01|01|11|DA|TA|...
              └async─┘└───── Preamble ────┘└───SFD────┘└─ Frame data ─...
```

CRS_DV remains asserted throughout the entire frame (preamble, SFD, payload, CRC) and only de-asserts after the last dibit.

**End of packet toggle pattern**: When the carrier ends before the PHY's elasticity buffer empties (common case), CRS_DV toggles at nibble rate to indicate CRS has dropped while DV remains:
- HIGH on second dibit of each nibble (data still valid)
- LOW on first dibit of each nibble (carrier lost)

```
End of frame with CRS ending before DV at 100M link mode:

REF_CLK:   _|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_
CRS_DV:    ‾‾‾‾‾‾‾‾‾‾|___|‾‾‾|___|‾‾‾|_______________
CRS:       ‾‾‾‾‾‾‾‾‾‾|______________________________
DV:        ‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾‾|_______________
RXD[1:0]:  ...data...|D0 |D1 |D2 |D3 |00 |00 |00 |00
                      └nibble┘└nibble┘
```

**Idle indication**: RXD[1:0] = 00 when CRS_DV is low.


### Practical Rx Sequence
1. Monitor CRS_DV for assertion
2. Wait for SFD pattern: dibits ending in "11" (0xD5 byte)
3. Sample RXD[1:0] on each REF_CLK rising while DV asserted (CRS_DV may toggle for DV assert)
4. Check RX_ER was never asserted during frame. Some PHYs emit invalid/preset data on RX[1:0] after RX_ER asserted
5. Assemble dibits into bytes (LSB first, same as Tx)
6. Validate CRC32 on assembled frame


## 10M vs 100M link mode Speed Differences

At 100 Mbps, RMII delivers one dibit per REF_CLK cycle (50 MHz × 2 bits = 100 Mbps).

At 10 Mbps, each dibit is **repeated 10 times** across 10 REF_CLK cycles:

```
100M: one dibit per clock
REF_CLK:   _|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_
RXD[1:0]:  |D0|D1|D2|D3|D4|D5|D6|D7|

10M: each dibit held for 10 clocks
REF_CLK:   _|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_|‾|_ ... (×10 per dibit)
RXD[1:0]:  |D0|D0|D0|D0|D0|D0|D0|D0|D0|D0|D1|D1|D1|...
```
