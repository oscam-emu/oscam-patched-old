#ifndef DRE_COMMON_H_
#define DRE_COMMON_H_

	int32_t dre_common_get_emm_type(EMM_PACKET *ep, struct s_reader *rdr);
	int32_t dre_common_get_emm_filter(struct s_reader *rdr, struct s_csystem_emm_filter **emm_filters, unsigned int *filter_count);

	uint8_t Drecrypt2OverCW(uint16_t overcryptId, uint8_t *cw);
	void Drecrypt2OverEMM(uint8_t *emm);
	void ReasmEMM82(uint8_t *emm);
	
#endif
