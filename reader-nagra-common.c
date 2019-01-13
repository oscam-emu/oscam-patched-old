#include "globals.h"
#include "reader-common.h"
#include "reader-nagra-common.h"

int32_t nagra_get_emm_type(EMM_PACKET *ep, struct s_reader *rdr) //returns 1 if shared emm matches SA, unique emm matches serial, or global or unknown
{
	switch(ep->emm[0])
	{
	case 0x83:
		memset(ep->hexserial, 0x00, 0x08);
		ep->hexserial[0] = ep->emm[5];
		ep->hexserial[1] = ep->emm[4];
		ep->hexserial[2] = ep->emm[3];
		if(ep->emm[7] == 0x10)
		{
			ep->type = SHARED;
			return (!memcmp(rdr->sa[0], ep->hexserial, 0x03));
		}
		else
		{
			ep->hexserial[3] = ep->emm[6];
			ep->type = UNIQUE;
			return (!memcmp(rdr->hexserial+2, ep->hexserial, 0x04));
		}
	case 0x82:
		ep->type = GLOBAL;
		return 1;
	default:
		ep->type = UNKNOWN;
		return 1;
	}
}

int32_t nagra_get_emm_filter(struct s_reader *rdr, struct s_csystem_emm_filter **emm_filters, unsigned int *filter_count)
{
	if(*emm_filters == NULL)
	{
		const unsigned int max_filter_count = 3;
		if(!cs_malloc(emm_filters, max_filter_count * sizeof(struct s_csystem_emm_filter)))
			{ return ERROR; }

		struct s_csystem_emm_filter *filters = *emm_filters;
		*filter_count = 0;

		int32_t idx = 0;

		filters[idx].type = EMM_UNIQUE;
		filters[idx].enabled   = 1;
		filters[idx].filter[0] = 0x83;
		filters[idx].filter[1] = rdr->hexserial[4];
		filters[idx].filter[2] = rdr->hexserial[3];
		filters[idx].filter[3] = rdr->hexserial[2];
		filters[idx].filter[4] = rdr->hexserial[5];
		filters[idx].filter[5] = 0x00;
		memset(&filters[idx].mask[0], 0xFF, 6);
		idx++;

		filters[idx].type = EMM_SHARED;
		filters[idx].enabled   = 1;
		filters[idx].filter[0] = 0x83;
		filters[idx].filter[1] = rdr->sa[0][2];
		filters[idx].filter[2] = rdr->sa[0][1];
		filters[idx].filter[3] = rdr->sa[0][0];
		filters[idx].filter[4] = 0x00;
		filters[idx].filter[5] = 0x10;
		memset(&filters[idx].mask[0], 0xFF, 6);
		idx++;

		filters[idx].type = EMM_GLOBAL;
		filters[idx].enabled   = 1;
		filters[idx].filter[0] = 0x82;
		filters[idx].mask[0]   = 0xFF;
		idx++;

		*filter_count = idx;
	}

	return OK;
}
