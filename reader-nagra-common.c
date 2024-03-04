#include "globals.h"
#include "reader-common.h"
#include "reader-nagra-common.h"

int32_t get_prov_idx(struct s_reader *rdr, const uint8_t *provid)
{
	int prov;
	for(prov = 0; prov < rdr->nprov; prov++) // search for provider index
	{
		if(!memcmp(provid, &rdr->prid[prov][2], 2))
		{
			return (prov);
		}
	}
	return (-1);
}

int32_t nagra_get_emm_type(EMM_PACKET *ep, struct s_reader *rdr)
{
	if(rdr->cak7type == 3 || rdr->autype == 1)
	{
		int i;

		switch(ep->emm[0])
		{
			case 0x82:
				memset(ep->hexserial, 0, 8);
				memcpy(ep->hexserial, ep->emm + 3, 6);
				if(!memcmp(rdr->hexserial, ep->hexserial, 6))
				{
					ep->type = UNIQUE;
					return 1;
				}
				else if ((ep->emm[3] == 0x00) && (ep->emm[4] == 0x00) && (ep->emm[5] == 0x00) && (ep->emm[6] == 0x00) && (ep->emm[7] == 0x00) && (ep->emm[8] == 0xD3) && (ep->emm[9] == 0x87))
				{
					ep->type = GLOBAL;
					return 1;
				}
				return 0;

			case 0x84:
				ep->type = SHARED;
				memset(ep->hexserial, 0, 8);
				memcpy(ep->hexserial, ep->emm + 5, 3);
				i = get_prov_idx(rdr, ep->emm + 3);

				if(i == -1)
				{
					return 0;
				}

				return (!memcmp(rdr->sa[i], ep->hexserial, 3));

			case 0x83:
				ep->type = GLOBAL;
				uint8_t filtr[] = {0x83, 0x00, 0x74};
				return (!memcmp(ep->emm, filtr, 3));

			case 0x90:
				ep->type = UNIQUE;
				if(rdr->cwpkcaid_length && rdr->nuid_length)
				{
					memset(ep->hexserial, 0x00, 0x08);
					ep->hexserial[0] = ep->emm[5];
					ep->hexserial[1] = ep->emm[4];
					ep->hexserial[2] = ep->emm[3];
					ep->hexserial[3] = ep->emm[6];
					return (!memcmp(rdr->nuid, ep->hexserial, 4));
				}
				return 0;

			default:
				ep->type = UNKNOWN;
				return 0;
		}
	}
	else if(rdr->cak7type == 1)
	{
		int i;
		switch(ep->emm[0])
		{
			case 0x82:
				ep->type = GLOBAL;
				if(rdr->emm82 == 1 && ep->emm[3] == 0x00 && ep->emm[4] == 0x00 && ep->emm[5] == 0x00)
				{
					return 1;
				}
				return 0;

			case 0x83:
				if(ep->emm[7] == 0x10)
				{
					ep->type = SHARED;

					for(i = 0; i < rdr->nemm83s; i++)
					{
						if(!memcmp(rdr->emm83s[i] + 1, ep->emm + 3, 0x03))
						{
							return 1;
						}
					}
				}
				else
				{
					ep->type = UNIQUE;

					for(i = 0; i < rdr->nemm83u; i++)
					{
						if(!memcmp(rdr->emm83u[i] + 1, ep->emm + 3, 0x04))
						{
							return 1;
						}
					}
				}
				return 0;

			case 0x84:
				ep->type = GLOBAL;

				for(i = 0; i < rdr->nemm84; i++)
				{
					if(!memcmp(rdr->emm84[i] + 1, ep->emm + 3, 0x02))
					{
						return 1;
					}
				}
				return 0;

			case 0x87:
				ep->type = SHARED;

				for(i = 0; i < rdr->nemm87; i++)
				{
					if(!memcmp(rdr->emm87[i] + 1, ep->emm + 3, 0x04))
					{
						return 1;
					}
				}
				return 0;

			case 0x90:
				ep->type = UNIQUE;
				if(rdr->cwpkcaid_length && rdr->nuid_length)
				{
					memset(ep->hexserial, 0x00, 0x08);
					ep->hexserial[0] = ep->emm[5];
					ep->hexserial[1] = ep->emm[4];
					ep->hexserial[2] = ep->emm[3];
					ep->hexserial[3] = ep->emm[6];
					return (!memcmp(rdr->nuid, ep->hexserial, 4));
				}
				return 0;

			default:
				ep->type = UNKNOWN;
				return 0;
		}
	}
	else if(rdr->autype == 2)
	{
		int i;
		switch(ep->emm[0])
		{
			case 0x82:
				ep->type = GLOBAL;
				if(ep->emm[3] == 0x00 && ep->emm[4] == 0x00 && ep->emm[5] == 0x00)
				{
					return 1;
				}
				return 0;

			case 0x83:
				memset(ep->hexserial, 0x00, 0x08);
				ep->hexserial[0] = ep->emm[5];
				ep->hexserial[1] = ep->emm[4];
				ep->hexserial[2] = ep->emm[3];
				if(ep->emm[7] == 0x10)
				{
					ep->type = SHARED;

					for(i = 0; i < rdr->nprov; i++)
					{
						if(!memcmp(rdr->sa[i], "\x00\x00\x00", 3))
						{
							continue;
						}

						if(!memcmp(rdr->sa[i], ep->hexserial, 0x03))
						{
							return 1;
						}
					}
				}
				else
				{
					ep->hexserial[3] = ep->emm[6];
					ep->type = UNIQUE;

					return (!memcmp(rdr->hexserial + 2, ep->hexserial, 0x04));
				}
				return 0;

			case 0x84:
				ep->type = GLOBAL;
				return 1;

			case 0x87:
				memset(ep->hexserial, 0x00, 0x08);
				ep->hexserial[0] = ep->emm[5];
				ep->hexserial[1] = ep->emm[4];
				ep->hexserial[2] = ep->emm[3];
				ep->hexserial[3] = ep->emm[6];
				ep->type = SHARED;

				for(i = 0; i < rdr->nprov; i++)
				{
					if(!memcmp(rdr->sa[i], "\x00\x00\x00", 3))
					{
						continue;
					}
					if(!memcmp(rdr->sa[i], ep->hexserial, 0x04))
					{
						return 1;
					}
				}
				return 0;

			default:
				ep->type = UNKNOWN;
				return 0;
		}
	}
	else
	{
		int i;
		switch(ep->emm[0])
		{
			case 0x82:
				memset(ep->hexserial, 0x00, 0x08);
				ep->hexserial[0] = ep->emm[5];
				ep->hexserial[1] = ep->emm[6];
				ep->hexserial[2] = ep->emm[7];
				ep->hexserial[3] = ep->emm[8];
				if (!memcmp(rdr->hexserial + 2, ep->hexserial, 0x04))
				{
					ep->type = UNIQUE;
					return 1;
				}
				else if ((ep->emm[3] == 0x00) && (ep->emm[4] == 0x00) && (ep->emm[5] == 0x00) && (ep->emm[6] == 0x00) && (ep->emm[7] == 0x00) && ((ep->emm[8] == 0x04) || (ep->emm[8] == 0xD3)) && ((ep->emm[9] == 0x84) || (ep->emm[9] == 0x8F) || (ep->emm[9] == 0x87)))
				{
					ep->type = GLOBAL;
					return 1;
				}
				return 0;
			
			case 0x84:
				memset(ep->hexserial, 0x00, 0x08);
				memcpy(ep->hexserial, ep->emm + 5, 3);
				if ((ep->emm[2] == 0x77) && (ep->emm[3] == 0x00))
				{
					ep->type = SHARED;
					i = get_prov_idx(rdr, ep->emm + 3);
					
					if(i == -1)
					{
						return 0;
					}

					return (!memcmp(rdr->sa[i], ep->hexserial, 3));
				}
				else if ((ep->emm[3] == 0x00) && ((ep->emm[4] == 0x71) || (ep->emm[4] == 0x32) || (ep->emm[4] == 0xEC)) && (ep->emm[5] == 0x00) && (ep->emm[6] == 0x00) && (ep->emm[7] == 0x00) && (ep->emm[8] == 0x04) && (ep->emm[9] == 0x84))
				{
					ep->type = GLOBAL;
					return 1;
				}
				return 0;

			case 0x83:
				memset(ep->hexserial, 0x00, 0x08);
				ep->hexserial[0] = ep->emm[5];
				ep->hexserial[1] = ep->emm[4];
				ep->hexserial[2] = ep->emm[3];
				ep->hexserial[3] = ep->emm[6];
				if(ep->emm[7] == 0x10)
				{
					ep->type = SHARED;

					for(i = 0; i < rdr->nprov; i++)
					{
						if(!memcmp(rdr->sa[i], "\x00\x00\x00", 3))
						{
							continue;
						}

						if(!memcmp(rdr->sa[i], ep->hexserial, 0x03))
						{
							return 1;
						}
					}
				}
				else if (!memcmp(rdr->hexserial + 2, ep->hexserial, 0x04))
				{
					ep->type = UNIQUE;
					return 1;
				}
				else if ((ep->emm[5] == 0x04) && (ep->emm[6] == 0x70))
				{
					ep->type = GLOBAL;
					return 1;				
				}
				return 0;

			case 0x87:
				ep->type = SHARED;
				return 1;

			default:
				ep->type = UNKNOWN;
				return 0;
		}
	}
}

int32_t nagra_get_emm_filter(struct s_reader *rdr, struct s_csystem_emm_filter **emm_filters, unsigned int *filter_count)
{
	if(rdr->cak7type == 3 || rdr->autype == 1)
	{
		if(*emm_filters == NULL)
		{
			const unsigned int max_filter_count = 2 + (2 * rdr->nprov);
			if(!cs_malloc(emm_filters, max_filter_count * sizeof(struct s_csystem_emm_filter)))
			{
				return ERROR;
			}

			struct s_csystem_emm_filter *filters = *emm_filters;
			*filter_count = 0;

			int32_t idx = 0;

			filters[idx].type = EMM_UNIQUE;
			filters[idx].enabled = 1;
			filters[idx].filter[0] = 0x82;
			filters[idx].mask[0] = 0xFF;
			memcpy(&filters[idx].filter[1], rdr->hexserial, 6);
			memset(&filters[idx].mask[1], 0xFF, 6);
			idx++;

			int32_t prov;
			for(prov = 0; prov < rdr->nprov; prov++)
			{
				if(!memcmp(rdr->sa[prov], "\x00\x00\x00", 3))
				{
					continue;
				}

				filters[idx].type = EMM_GLOBAL;
				filters[idx].enabled = 1;
				filters[idx].filter[0] = 0x83;
				filters[idx].mask[0] = 0xFF;
				memcpy(&filters[idx].filter[1], &rdr->prid[prov][2], 2);
				memset(&filters[idx].mask[1], 0xFF, 2);
				idx++;

				filters[idx].type = EMM_SHARED;
				filters[idx].enabled = 1;
				filters[idx].filter[0] = 0x84;
				filters[idx].mask[0] = 0xFF;
				memcpy(&filters[idx].filter[1], &rdr->prid[prov][2], 2);
				memset(&filters[idx].mask[1], 0xFF, 2);
				memcpy(&filters[idx].filter[3], &rdr->sa[prov], 3);
				memset(&filters[idx].mask[3], 0xFF, 3);
				idx++;
			}

			if(rdr->cwpkcaid_length && rdr->nuid_length)
			{
				filters[idx].type = EMM_UNIQUE;
				filters[idx].enabled = 1;
				filters[idx].filter[0] = 0x90;
				filters[idx].filter[1] = rdr->nuid[2];
				filters[idx].filter[2] = rdr->nuid[1];
				filters[idx].filter[3] = rdr->nuid[0];
				filters[idx].filter[4] = rdr->nuid[3];
				memset(&filters[idx].mask[0], 0xFF, 5);
				idx++;
			}

			*filter_count = idx;
		}

		return OK;
	}
	else if(rdr->cak7type == 1)
	{
		if(*emm_filters == NULL)
		{
			const unsigned int max_filter_count = 2 + (4 * rdr->nprov);
			if(!cs_malloc(emm_filters, max_filter_count * sizeof(struct s_csystem_emm_filter)))
			{
				return ERROR;
			}

			struct s_csystem_emm_filter *filters = *emm_filters;
			*filter_count = 0;

			int32_t idx = 0;

			if(rdr->emm82 == 1)
			{
				filters[idx].type = EMM_GLOBAL;
				filters[idx].enabled = 1;
				filters[idx].filter[0] = 0x82;
				filters[idx].mask[0] = 0xFF;
				idx++;
			}

			int32_t i;
			for(i = 0; i < rdr->nemm83u; i++)
			{
				filters[idx].type = EMM_UNIQUE;
				filters[idx].enabled = 1;
				memcpy(&filters[idx].filter[0], rdr->emm83u[i], 6);
				memset(&filters[idx].mask[0], 0xFF, 6);
				idx++;
			}

			for(i = 0; i < rdr->nemm83s; i++)
			{
				filters[idx].type = EMM_SHARED;
				filters[idx].enabled = 1;
				memcpy(&filters[idx].filter[0], rdr->emm83s[i], 6);
				memset(&filters[idx].mask[0], 0xFF, 6);
				idx++;
			}

			for(i = 0; i < rdr->nemm84; i++)
			{
				filters[idx].type = EMM_GLOBAL;
				filters[idx].enabled = 1;
				memcpy(&filters[idx].filter[0], rdr->emm84[i], 3);
				memset(&filters[idx].mask[0], 0xFF, 3);
				idx++;
			}

			for(i = 0; i < rdr->nemm87; i++)
			{
				filters[idx].type = EMM_SHARED;
				filters[idx].enabled = 1;
				memcpy(&filters[idx].filter[0], rdr->emm87[i], 6);
				memset(&filters[idx].mask[0], 0xFF, 6);
				idx++;
			}

			if(rdr->cwpkcaid_length && rdr->nuid_length)
			{
				filters[idx].type = EMM_UNIQUE;
				filters[idx].enabled = 1;
				filters[idx].filter[0] = 0x90;
				filters[idx].filter[1] = rdr->nuid[2];
				filters[idx].filter[2] = rdr->nuid[1];
				filters[idx].filter[3] = rdr->nuid[0];
				filters[idx].filter[4] = rdr->nuid[3];
				memset(&filters[idx].mask[0], 0xFF, 5);
				idx++;
			}

			*filter_count = idx;
		}

		return OK;
	}
	else if(rdr->autype == 2)
	{
		if(*emm_filters == NULL)
		{
			const unsigned int max_filter_count = 3 + (2 * rdr->nprov);
			if(!cs_malloc(emm_filters, max_filter_count * sizeof(struct s_csystem_emm_filter)))
			{
				return ERROR;
			}

			struct s_csystem_emm_filter *filters = *emm_filters;
			*filter_count = 0;

			int32_t idx = 0;

			filters[idx].type = EMM_GLOBAL;
			filters[idx].enabled = 1;
			filters[idx].filter[0] = 0x82;
			filters[idx].mask[0] = 0xFF;
			idx++;

			filters[idx].type = EMM_GLOBAL;
			filters[idx].enabled = 1;
			filters[idx].filter[0] = 0x84;
			filters[idx].mask[0] = 0xFF;
			idx++;

			filters[idx].type = EMM_UNIQUE;
			filters[idx].enabled = 1;
			filters[idx].filter[0] = 0x83;
			filters[idx].filter[1] = rdr->hexserial[4];
			filters[idx].filter[2] = rdr->hexserial[3];
			filters[idx].filter[3] = rdr->hexserial[2];
			filters[idx].filter[4] = rdr->hexserial[5];
			filters[idx].filter[5] = 0x00;
			memset(&filters[idx].mask[0], 0xFF, 6);
			idx++;

			int i;
			for(i = 0; i < rdr->nprov; i++)
			{
				if(!memcmp(rdr->sa[i], "\x00\x00\x00", 3))
				{
					continue;
				}

				filters[idx].type = EMM_SHARED;
				filters[idx].enabled = 1;
				filters[idx].filter[0] = 0x83;
				filters[idx].filter[1] = rdr->sa[i][2];
				filters[idx].filter[2] = rdr->sa[i][1];
				filters[idx].filter[3] = rdr->sa[i][0];
				filters[idx].filter[4] = 0x00;
				filters[idx].filter[5] = 0x10;
				memset(&filters[idx].mask[0], 0xFF, 6);
				idx++;

				filters[idx].type = EMM_SHARED;
				filters[idx].enabled = 1;
				filters[idx].filter[0] = 0x87;
				filters[idx].filter[1] = rdr->sa[i][2];
				filters[idx].filter[2] = rdr->sa[i][1];
				filters[idx].filter[3] = rdr->sa[i][0];
				filters[idx].filter[4] = rdr->sa[i][3];
				filters[idx].filter[5] = 0x00;
				memset(&filters[idx].mask[0], 0xFF, 6);
				idx++;
			}

			*filter_count = idx;
		}

		return OK;
	}
	else
	{
		if(*emm_filters == NULL)
		{
			const unsigned int max_filter_count = 6 + (2 * rdr->nprov);
			if(!cs_malloc(emm_filters, max_filter_count * sizeof(struct s_csystem_emm_filter)))
			{
				return ERROR;
			}

			struct s_csystem_emm_filter *filters = *emm_filters;
			*filter_count = 0;

			int32_t idx = 0;

			filters[idx].type = EMM_UNIQUE;
			filters[idx].enabled = 1;
			filters[idx].filter[0] = 0x82;
			filters[idx].mask[0] = 0xFF;
			memcpy(&filters[idx].filter[1], rdr->hexserial, 6);
			memset(&filters[idx].mask[1], 0xFF, 6);
			idx++;

			filters[idx].type = EMM_UNIQUE;
			filters[idx].enabled = 1;
			filters[idx].filter[0] = 0x83;
			filters[idx].filter[1] = rdr->hexserial[4];
			filters[idx].filter[2] = rdr->hexserial[3];
			filters[idx].filter[3] = rdr->hexserial[2];
			filters[idx].filter[4] = rdr->hexserial[5];
			filters[idx].filter[5] = 0x00;
			memset(&filters[idx].mask[0], 0xFF, 6);
			idx++;

			filters[idx].type = EMM_SHARED;
			filters[idx].enabled = 1;
			filters[idx].filter[0] = 0x87;
			filters[idx].mask[0] = 0xFF;
			idx++;

			filters[idx].type = EMM_GLOBAL;
			filters[idx].enabled = 1;
			filters[idx].filter[0] = 0x82;
			filters[idx].mask[0] = 0xFF;
			idx++;

			filters[idx].type = EMM_GLOBAL;
			filters[idx].enabled = 1;
			filters[idx].filter[0] = 0x84;
			filters[idx].mask[0] = 0xFF;
			idx++;

			filters[idx].type = EMM_GLOBAL;
			filters[idx].enabled = 1;
			filters[idx].filter[0] = 0x83;
			filters[idx].mask[0] = 0xFF;
			idx++;

			int32_t prov;
			for(prov = 0; prov < rdr->nprov; prov++)
			{
				if(!memcmp(rdr->sa[prov], "\x00\x00\x00", 3))
				{
					continue;
				}

				filters[idx].type = EMM_SHARED;
				filters[idx].enabled = 1;
				filters[idx].filter[0] = 0x84;
				filters[idx].mask[0] = 0xFF;
				memcpy(&filters[idx].filter[1], &rdr->prid[prov][2], 2);
				memset(&filters[idx].mask[1], 0xFF, 2);
				memcpy(&filters[idx].filter[3], &rdr->sa[prov], 3);
				memset(&filters[idx].mask[3], 0xFF, 3);
				idx++;

				filters[idx].type = EMM_SHARED;
				filters[idx].enabled = 1;
				filters[idx].filter[0] = 0x83;
				filters[idx].filter[1] = rdr->sa[prov][2];
				filters[idx].filter[2] = rdr->sa[prov][1];
				filters[idx].filter[3] = rdr->sa[prov][0];
				filters[idx].filter[4] = 0x00;
				filters[idx].filter[5] = 0x10;
				memset(&filters[idx].mask[0], 0xFF, 6);
				idx++;
			}

			*filter_count = idx;
		}

		return OK;
	}
}
