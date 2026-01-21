# RMII guide
This guide exists because information on how to structure MII/RMII data is hard to come by. It is also not helpful that asking an AI that is also provided datasheets with accurate information on the subject will return garbage information. Thus the need to document this so that X person can deterministically find this info.


## Tx0/Tx1/TxEN and CLKREF/RETCLK interface
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
