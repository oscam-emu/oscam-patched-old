#ifndef MODULE_EMULATOR_POWERVU_H
#define MODULE_EMULATOR_POWERVU_H

#ifdef WITH_EMU

#define PVU_CW_VID	0	// VIDeo
#define PVU_CW_HSD	1	// High Speed Data
#define PVU_CW_A1	2	// Audio 1
#define PVU_CW_A2	3	// Audio 2
#define PVU_CW_A3	4	// Audio 3
#define PVU_CW_A4	5	// Audio 4
#define PVU_CW_UTL	6	// UTiLity
#define PVU_CW_VBI	7	// Vertical Blanking Interval

#define PVU_CONVCW_VID_ECM	0x80	// VIDeo
#define PVU_CONVCW_HSD_ECM	0x40	// High Speed Data
#define PVU_CONVCW_A1_ECM	0x20	// Audio 1
#define PVU_CONVCW_A2_ECM	0x10	// Audio 2
#define PVU_CONVCW_A3_ECM	0x08	// Audio 3
#define PVU_CONVCW_A4_ECM	0x04	// Audio 4
#define PVU_CONVCW_UTL_ECM	0x02	// UTiLity
#define PVU_CONVCW_VBI_ECM	0x01	// Vertical Blanking Interval

int8_t PowervuECM(uint8_t *ecm, uint8_t *dw, uint16_t srvid, emu_stream_client_key_data *cdata, EXTENDED_CW* cw_ex);
int8_t PowervuEMM(uint8_t *emm, uint32_t *keysAdded);

// hexserials must be of type "uint8_t hexserials[length][4]"
// if srvid == 0xFFFF all serials are returned (no srvid filtering)
// returns 0 on error, 1 on success
int8_t GetPowervuHexserials(uint16_t srvid, uint8_t hexserials[][4], int32_t length, int32_t* count);

#endif // WITH_EMU

#endif // MODULE_EMULATOR_POWERVU_H
