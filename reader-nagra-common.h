#ifndef READER_NAGRA_COMMON_H_
#define READER_NAGRA_COMMON_H_

#define SYSTEM_NAGRA 0x1800
#define SYSTEM_MASK 0xFF00

int32_t nagra_get_emm_type(EMM_PACKET *ep, struct s_reader *rdr);
int32_t nagra_get_emm_filter(struct s_reader *rdr, struct s_csystem_emm_filter **emm_filters, unsigned int *filter_count);

#endif
