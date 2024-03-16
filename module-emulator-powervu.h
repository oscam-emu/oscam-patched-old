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

#ifdef MODULE_STREAMRELAY
int8_t powervu_ecm(uint8_t *ecm, uint8_t *dw, EXTENDED_CW *cw_ex, uint16_t srvid, uint16_t caid, uint16_t tsid, uint16_t onid, uint32_t ens, emu_stream_client_key_data *cdata);
#else
int8_t powervu_ecm(uint8_t *ecm, uint8_t *dw, EXTENDED_CW *cw_ex, uint16_t srvid, uint16_t caid, uint16_t tsid, uint16_t onid, uint32_t ens);
#endif
int8_t powervu_emm(uint8_t *emm, uint32_t *keysAdded);

/*
 * This function searches for EMM keys and adds their Unique Addresses (UA) as EMM filters.
 * The EMM keys are picked from all group id's that have ECM keys for the srvid specified
 * as input. If there is a large ammount of EMM keys matching these criteria, only the first
 * "maxCount" UA's are added as EMM filters. The rest are not used at all.
 *
 * In the rare case where two or more EMM keys with the same UA belong to different groups,
 * and these groups also have ECM keys for the srvid in request, there is a chance the ECM
 * keys in the "wrong" group to be updated. This is because the EMM algorithm has no way of
 * knowing in which group the service id belongs to. A workaround for this designing flaw
 * is to make sure there are no EMM keys with the same UA between different groups.
 *
 * Hexserials must be of type "uint8_t hexserials[maxCount][4]". If srvid is equal to 0xFFFF
 * all serials are added (no service id filtering is done). Returns the count of hexserials
 * added as filters.
*/
int8_t powervu_get_hexserials(uint8_t hexserials[][4], uint32_t maxCount, uint16_t srvid);

/*
 * Like the previous function, it adds UAs as EMM filters. It is used in conjunction with the
 * new method of entering ECM keys, where one key can serve every channel in the group. Since
 * there is no srvid to search for, we need to know the group id prior to searching for EMM
 * keys. To do so, this function calulates a hash using the tsid, onid and enigma namespace of
 * the transponder, which is only available in enigma2.
 *
 * Hexserials must be of type "uint8_t hexserials[maxCount][4]" like before. It returns the
 * count of hexserials added as filters.
*/
int8_t powervu_get_hexserials_new(uint8_t hexserials[][4], uint32_t maxCount, uint16_t caid, uint16_t tsid, uint16_t onid, uint32_t ens);

#endif // WITH_EMU

#endif // MODULE_EMULATOR_POWERVU_H
