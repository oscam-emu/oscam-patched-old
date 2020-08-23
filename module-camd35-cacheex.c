#define MODULE_LOG_PREFIX "camd35"

#include "globals.h"
#include "oscam-array.h"

#if defined(CS_CACHEEX) && (defined(MODULE_CAMD35) || defined(MODULE_CAMD35_TCP))

#include "module-cacheex.h"
#include "module-camd35.h"
#include "module-camd35-cacheex.h"
#include "oscam-cache.h"
#include "oscam-client.h"
#include "oscam-ecm.h"
#include "oscam-string.h"
#include "oscam-reader.h"
#include "oscam-chk.h"
#include "oscam-config.h"

uint8_t camd35_node_id[8];

#define CSP_HASH_SWAP(n) (((((uint32_t)(n) & 0xFF)) << 24) | \
                  ((((uint32_t)(n) & 0xFF00)) << 8) | \
                  ((((uint32_t)(n) & 0xFF0000)) >> 8) | \
                  ((((uint32_t)(n) & 0xFF000000)) >> 24))

void camd35_cacheex_feature_trigger_in(struct s_client *cl, uint8_t *buf)
{
	int32_t feature = 0;
	uint16_t i = 20;
	uint8_t filter_count;
	uint8_t j, k, l, rc;
	feature = buf[21] | (buf[20] << 8);
	FTAB *lgonly_tab;

	switch(feature)
	{
		// set localgenerated only
		case 1:
			if(cl->typ == 'c' && (cl->account->cacheex.mode == 2 || cl->account->cacheex.mode == 1))
			{
				if(cfg.cacheex_lg_only_remote_settings || cl->account->cacheex.lg_only_remote_settings)
					cl->account->cacheex.localgenerated_only = buf[24];
				else if(buf[24])
					cl->account->cacheex.localgenerated_only = buf[24];
			}
			else if(cl->typ == 'p' && cl->reader->cacheex.mode == 3)
			{
				if(cfg.cacheex_lg_only_remote_settings || cl->reader->cacheex.lg_only_remote_settings)
					cl->reader->cacheex.localgenerated_only = buf[24];
				else if(buf[24])
					cl->reader->cacheex.localgenerated_only = buf[24];
			}
			break;
		// set localgenerated only caidtab
		case 2:
			filter_count = buf[i+4];
			i += 5;

			memset(&lgonly_tab, 0, sizeof(lgonly_tab));

			if(cl->typ == 'c' && (cl->account->cacheex.mode == 2 ||cl->account->cacheex.mode == 1))
			{
				lgonly_tab = &cl->account->cacheex.lg_only_tab;
			}
			else if(cl->typ == 'p' && cl->reader->cacheex.mode == 3)
			{
				lgonly_tab = &cl->reader->cacheex.lg_only_tab;
			}

			// remotesettings enabled - replace local settings
			if(cfg.cacheex_lg_only_remote_settings ||
				(
						(cl->typ == 'c' && (cl->account->cacheex.mode == 2 ||cl->account->cacheex.mode == 1) && cl->account->cacheex.lg_only_remote_settings)
					|| 	(cl->typ == 'p' && cl->reader->cacheex.mode == 3 && cl->reader->cacheex.lg_only_remote_settings)
				)
			)
			{
				ftab_clear(lgonly_tab);

				for(j = 0; j < filter_count; j++)
				{
					FILTER d;
					memset(&d, 0, sizeof(d));
					
					d.caid = b2i(2, buf + i);
					i += 2;

					d.nprids = 1;
					d.prids[0] = NO_PROVID_VALUE;

					ftab_add(lgonly_tab, &d);
				}
			}
			// remotesettings disabled - write additional remote-caids received
			else
			{
				for(j = 0; j < filter_count; j++)
				{
					FILTER d;
					memset(&d, 0, sizeof(d));
					
					d.caid = b2i(2, buf + i);
					i += 2;

					d.nprids = 1;
					d.prids[0] = NO_PROVID_VALUE;

					if(!chk_lg_only_cp(d.caid, d.prids[0], lgonly_tab))
					{
						cs_log_dbg(D_CACHEEX, "%04X:%06X not found in local settings - adding them", d.caid, d.prids[0]);

						for(l = rc = 0; (!rc) && (l < lgonly_tab->nfilts); l++)
						{
							if(lgonly_tab->filts[l].caid == d.caid)
							{
								rc = 1;
								
								if(lgonly_tab->filts[l].nprids+1 <= CS_MAXPROV)
								{
									lgonly_tab->filts[l].prids[lgonly_tab->filts[l].nprids] = d.prids[0];
									lgonly_tab->filts[l].nprids++;
								}
								else
								{
									cs_log_dbg(D_CACHEEX, "error: cacheex_lg_only_tab -> max. number(%i) of providers reached", CS_MAXPROV);
								}
							}
						}
						if(!rc)
						{
							ftab_add(lgonly_tab, &d);
						}
					}
				}
			}
			break;
		// set cacheex_ecm_filter - extended
		case 4:
			filter_count = buf[i+4];
			i += 5;

			CECSPVALUETAB *filter;
			memset(&filter, 0, sizeof(filter));
			
			if(cl->typ == 'c' && (cl->account->cacheex.mode == 2 ||cl->account->cacheex.mode == 1) && cl->account->cacheex.allow_filter)
			{
				filter = &cl->account->cacheex.filter_caidtab;
			}
			else if(cl->typ == 'p' && cl->reader->cacheex.mode == 3 && cl->reader->cacheex.allow_filter)
			{
				filter = &cl->reader->cacheex.filter_caidtab;
			}

			cecspvaluetab_clear(filter);

			for(j = 0; j < filter_count; j++)
			{
				int32_t caid = -1, cmask = -1, provid = -1, srvid = -1;
				CECSPVALUETAB_DATA d;
				memset(&d, 0, sizeof(d));
				
				caid = b2i(2, buf + i);
				if(caid == 0xFFFF) caid = -1;
				i += 2;
				
				cmask = b2i(2, buf + i);
				if(cmask == 0xFFFF) cmask = -1;
				i += 2;

				provid = b2i(3, buf + i);
				if(provid == 0xFFFFFF) provid = -1;
				i += 3;

				srvid = b2i(2, buf + i);
				if(srvid == 0xFFFF) srvid = -1;
				i += 2;
				
				if(caid > 0)
				{
					d.caid = caid;
					d.cmask = cmask;
					d.prid = provid;
					d.srvid = srvid;
					cecspvaluetab_add(filter, &d);
				}
			}
			break;
		// no push after
		case 8: ;
			CAIDVALUETAB *ctab;
			memset(&ctab, 0, sizeof(ctab));

			if(cl->typ == 'c' && (cl->account->cacheex.mode == 2 ||cl->account->cacheex.mode == 1))
				{
					ctab = &cl->account->cacheex.cacheex_nopushafter_tab;
				}
				else if(cl->typ == 'p' && cl->reader->cacheex.mode == 3)
				{
					ctab = &cl->reader->cacheex.cacheex_nopushafter_tab;
				}

			filter_count = buf[i+4];
			i += 5;
			
			caidvaluetab_clear(ctab);

			for(j = 0; j < filter_count; j++)
			{
				uint16_t caid = 0, value = 0;
				CAIDVALUETAB_DATA d;
				memset(&d, 0, sizeof(d));

				caid = b2i(2, buf + i);
				if(caid == 0xFFFF) caid = -1;
				i += 2;
				
				value = b2i(2, buf + i);
				if(value == 0xFFFF) value = -1;
				i += 2;
				
				if(caid > 0)
				{
					d.caid = caid;
					d.value = value;
					caidvaluetab_add(ctab, &d);
				}
			}
			break;
		// max hop
		case 16:
			if(cl->typ == 'c' && (cl->account->cacheex.mode == 2 ||cl->account->cacheex.mode == 1) && cl->account->cacheex.allow_maxhop)
			{
				cl->account->cacheex.maxhop = buf[24];
				cl->account->cacheex.maxhop_lg = buf[25];
			}
			else if(cl->typ == 'p' && cl->reader->cacheex.mode == 3 && cl->reader->cacheex.allow_maxhop)
			{
				cl->reader->cacheex.maxhop = buf[24];
				cl->reader->cacheex.maxhop_lg = buf[25];
			}
			break;
		// aio-version
		case 32:
			if(cl->typ == 'c' && cl->account->cacheex.mode > 0)
			{
				char *ofs = (char *)buf + i + 4;
				cs_strncpy(cl->account->cacheex.aio_version, ofs, sizeof(cl->account->cacheex.aio_version));
			}
			else if(cl->typ == 'p' && cl->reader->cacheex.mode > 0)
			{
				char *ofs = (char *)buf + i + 4;
				cs_strncpy(cl->reader->cacheex.aio_version, ofs, sizeof(cl->reader->cacheex.aio_version));
			}
			break;
		// lg_only_tab caid:prov1[,provN][;caid:prov]
		case 64: ;
			memset(&lgonly_tab, 0, sizeof(lgonly_tab));

			if(cl->typ == 'c' && (cl->account->cacheex.mode == 2 ||cl->account->cacheex.mode == 1))
			{
				lgonly_tab = &cl->account->cacheex.lg_only_tab;
			}
			else if(cl->typ == 'p' && cl->reader->cacheex.mode == 3)
			{
				lgonly_tab = &cl->reader->cacheex.lg_only_tab;
			}

			filter_count = buf[i+4];
			i += 5;

			// remotesettings enabled - replace local settings
			if(cfg.cacheex_lg_only_remote_settings ||
				(
						(cl->typ == 'c' && (cl->account->cacheex.mode == 2 ||cl->account->cacheex.mode == 1) && cl->account->cacheex.lg_only_remote_settings)
					|| 	(cl->typ == 'p' && cl->reader->cacheex.mode == 3 && cl->reader->cacheex.lg_only_remote_settings)
					||  !lgonly_tab->nfilts
				)
			)
			{
				ftab_clear(lgonly_tab);

				for(j = 0; j < filter_count; j++)
				{
					FILTER d;
					memset(&d, 0, sizeof(d));
					
					d.caid = b2i(2, buf + i);
					i += 2;

					d.nprids = b2i(1, buf + i);
					i += 1;

					for(k=0; k < d.nprids; k++)
					{
						d.prids[k] = b2i(3, buf + i);
						i += 3;
					}
					ftab_add(lgonly_tab, &d);

				}
			}
			// remotesettings disabled - write additional remote-caid/provids received
			else
			{
				for(j = 0; j < filter_count; j++)
				{
					FILTER d;
					memset(&d, 0, sizeof(d));
					
					d.caid = b2i(2, buf + i);
					i += 2;

					d.nprids = b2i(1, buf + i);
					i += 1;

					for(k=0; k < d.nprids; k++)
					{
						d.prids[k] = b2i(3, buf + i);
						i += 3;

						if(!chk_ident_filter(d.caid, d.prids[k], lgonly_tab))
						{
							cs_log_dbg(D_CACHEEX, "%04X:%06X not found in local settings - adding them", d.caid, d.prids[k]);

							for(l = rc = 0; (!rc) && (l < lgonly_tab->nfilts); l++)
							{
								if(lgonly_tab->filts[l].caid == d.caid)
								{
									rc = 1;
									
									if(lgonly_tab->filts[l].nprids+1 <= CS_MAXPROV)
									{
										lgonly_tab->filts[l].prids[lgonly_tab->filts[l].nprids] = d.prids[k];
										lgonly_tab->filts[l].nprids++;
									}	
									else
									{
										cs_log_dbg(D_CACHEEX, "error: cacheex_lg_only_tab -> max. number of providers reached");
									}
								}
							}
							if(!rc)
							{
								ftab_add(lgonly_tab, &d);
							}	
						}
					}
				}
			}			
			break;
		default:
			return;
	}
}

void camd35_cacheex_feature_trigger(struct s_client *cl, int32_t feature, uint8_t mode)
{
	// size: 20 + (feature-bitfield & mask: 2) + payload-size: 2 + feature-payload :x
	uint16_t size = 20 + 2 + 2;
	int i = 0;
	uint8_t j;
	uint8_t payload[MAX_ECM_SIZE-size]; 
	memset(payload, 0, sizeof(payload));

	switch(feature)
	{
		FTAB *lgonly_tab;
		// set localgenerated only
		case 1:
			size += 1;
			if(size < 32)
				size = 32;

			// bitfield
			i2b_buf(2, feature, payload + i);
			i += 2;
			// payload-size
			i2b_buf(2, 1, payload + i);
			i += 2;
			// set payload
			if(mode == 2)
			{
				if(cl->reader->cacheex.localgenerated_only_in)
					payload[i] = cl->reader->cacheex.localgenerated_only_in;
				else
					payload[i] = cfg.cacheex_localgenerated_only_in;
				i += 1;
			}
			else if(mode == 3)
			{
				if(cl->account->cacheex.localgenerated_only_in)
					payload[i] = cl->account->cacheex.localgenerated_only_in;
				else
					payload[i] = cfg.cacheex_localgenerated_only_in;
				i += 1;
			}
			
			break;
		// set localgenerated only caidtab; cx-aio < 9.2.6-04
		case 2: ;
			if(mode == 2)
			{
				lgonly_tab = &cl->reader->cacheex.lg_only_in_tab;
				if(!lgonly_tab->nfilts)
					lgonly_tab = &cfg.cacheex_lg_only_in_tab;
			}
			else if(mode == 3)
			{
				lgonly_tab = &cl->account->cacheex.lg_only_in_tab;
				if(!lgonly_tab->nfilts)
					lgonly_tab = &cfg.cacheex_lg_only_in_tab;
			}
			else
			{
				return;
			}

			size += (lgonly_tab->nfilts * 2 + 1);
			if(size < 32)
				size = 32;

			// bitfield
			i2b_buf(2, feature, payload + i);
			i += 2;
			// payload-size
			if((lgonly_tab->nfilts * 2 + 1) > (int)sizeof(payload))
			{
				cs_log_dbg(D_CACHEEX, "ERROR: too much localgenerated only caidtab-entries (max. 255)");
				return;
			}
			i2b_buf(2, (lgonly_tab->nfilts * 2 + 1), payload + i); // n * caid + ctnum
			i += 2;
			// set payload
			if(lgonly_tab->nfilts > 255)
			{
				cs_log_dbg(D_CACHEEX, "ERROR: too much localgenerated only caidtab-entries (max. 255)");
				return;
			}
			payload[i] = lgonly_tab->nfilts;
			i += 1;

			for(j = 0; j < lgonly_tab->nfilts; j++)
			{
				FILTER *d = &lgonly_tab->filts[j];
				if(d->caid)
				{
					i2b_buf(2, d->caid, payload + i);
					i += 2;
				}
				else
				{
					continue;
				}
			}
			break;
		// cacchex_ecm_filter extendend
		case 4: ;
			CECSPVALUETAB *filter;
			if(mode == 2)
			{
				filter = &cl->reader->cacheex.filter_caidtab;
				// if not set, use global settings
				if(cl->reader->cacheex.filter_caidtab.cevnum == 0 && cfg.cacheex_filter_caidtab.cevnum > 0)
					filter = &cfg.cacheex_filter_caidtab;
				// if aio, use global aio settings
				if(cl->reader->cacheex.filter_caidtab.cevnum == 0 && cfg.cacheex_filter_caidtab_aio.cevnum > 0 && cl->cacheex_aio_checked && (cl->reader->cacheex.feature_bitfield & 4))
					filter = &cfg.cacheex_filter_caidtab_aio;
			}
			else if(mode == 3)
			{

				filter = &cl->account->cacheex.filter_caidtab;
				// if not set, use global settings
				if(cl->account->cacheex.filter_caidtab.cevnum == 0 && cfg.cacheex_filter_caidtab.cevnum > 0)
					filter = &cfg.cacheex_filter_caidtab;
				if(cl->account->cacheex.filter_caidtab.cevnum == 0 && cfg.cacheex_filter_caidtab_aio.cevnum > 0 && cl->cacheex_aio_checked && (cl->account->cacheex.feature_bitfield & 4))
					filter = &cfg.cacheex_filter_caidtab_aio;
			}
			else
			{
				return;
			}

			size += (filter->cevnum * 9 + 1);
			if(size < 32)
				size = 32;

			// bitfield
			i2b_buf(2, feature, payload + i);
			i += 2;
			// payload-size
			if((filter->cevnum * 9 + 1) > (int)sizeof(payload))
			{
				cs_log_dbg(D_CACHEEX, "ERROR: to much cacheex_ecm_filter-entries (max. 63), only 15 default camd3-filters sent");
				return;
			}
			i2b_buf(2, (filter->cevnum * 9 + 1), payload + i); // n * (caid2,mask2,provid3,srvid2) + ctnum1
			i += 2;
			// set payload
			payload[i] = filter->cevnum;
			i += 1;

			for(j = 0; j < filter->cevnum; j++)
			{
				CECSPVALUETAB_DATA *d = &filter->cevdata[j];
				if(d->caid)
				{
					i2b_buf(2, d->caid, payload + i);
					i += 2;
				}
				if(d->cmask)
				{
					i2b_buf(2, d->cmask, payload + i);
				}
				i += 2;

				if(d->prid)
				{
					i2b_buf(3, d->prid, payload + i);
				}
				i += 3;

				if(d->srvid)
				{
					i2b_buf(2, d->srvid, payload + i);
				}
				i += 2;
			}

			camd35_cacheex_send_push_filter(cl, 2);
			break;
		// no push after
		case 8: ;
			CAIDVALUETAB *ctab;
			if(mode == 2)
			{
				ctab = &cl->reader->cacheex.cacheex_nopushafter_tab;
				if(!ctab->cvnum)
					ctab = &cfg.cacheex_nopushafter_tab;
			}
			else if(mode == 3)
			{
				ctab = &cl->account->cacheex.cacheex_nopushafter_tab;
				if(!ctab->cvnum)
					ctab = &cfg.cacheex_nopushafter_tab;
			}
			else
			{
				return;
			}

			size += (ctab->cvnum * 4 + 1);
			if(size < 32)
				size = 32;

			// bitfield
			i2b_buf(2, feature, payload + i);
			i += 2;
			// payload-size
			if((ctab->cvnum * 4 + 1) > (int)sizeof(payload))
			{
				cs_log_dbg(D_CACHEEX, "ERROR: to much no push after caidtvalueab-entries (max. 255)");
				return;
			}
			i2b_buf(2, (ctab->cvnum * 4 + 1), payload + i); // n * (caid2+value2) + cvnum
			i += 2;
			// set payload
			if(ctab->cvnum > 255)
			{
				cs_log_dbg(D_CACHEEX, "ERROR: to much no push after caidtvalueab-entries (max. 255)");
				return;
			}
			payload[i] = ctab->cvnum;
			i += 1;

			for(j = 0; j < ctab->cvnum; j++)
			{
				CAIDVALUETAB_DATA *d = &ctab->cvdata[j];
				if(d->caid)
				{
					i2b_buf(2, d->caid, payload + i);
					i += 2;
					i2b_buf(2, d->value, payload + i);
					i += 2;
				}
				else
				{
					continue;
				}
			}
			break;
		// maxhop
		case 16:
			size += 2;
			if(size < 32)
				size = 32;

			// bitfield
			i2b_buf(2, feature, payload + i);
			i += 2;
			// payload-size
			i2b_buf(2, 2, payload + i);
			i += 2;
			// set payload
			if(mode == 2)
			{
				if(cl->reader->cacheex.maxhop)
					payload[i] = cl->reader->cacheex.maxhop;
				else
					payload[i] = 0;
				i += 1;

				if(cl->reader->cacheex.maxhop_lg)
					payload[i] = cl->reader->cacheex.maxhop_lg;
				else
					payload[i] = 0;
			}
			else if(mode == 3)
			{
				if(cl->account->cacheex.maxhop)
					payload[i] = cl->account->cacheex.maxhop;
				else
					payload[i] = 0;
				i += 1;

				if(cl->account->cacheex.maxhop_lg)
					payload[i] = cl->account->cacheex.maxhop_lg;
				else
					payload[i] = 0;
			}
			break;
		// aio-version
		case 32: ;
			size += 12;
			if(size < 32)
				size = 32;

			uint8_t token[12];

			// bitfield
			i2b_buf(2, feature, payload + i);
			i += 2;
			// payload-size
			i2b_buf(2, sizeof(token), payload + i);
			i += 2;
			// set payload
			
			snprintf((char *)token, sizeof(token), "%s", CS_AIO_VERSION);
			uint8_t *ofs = payload + i;
			memcpy(ofs, token, sizeof(token));
			break;
		// lg_only_tab
		case 64: ;
			// bitfield
			i2b_buf(2, feature, payload + i);
			i += 2;

			if(mode == 2)
			{
				lgonly_tab = &cl->reader->cacheex.lg_only_in_tab;
				if(!lgonly_tab->nfilts)
					lgonly_tab = &cfg.cacheex_lg_only_in_tab;
			}
			else if(mode == 3)
			{
				lgonly_tab = &cl->account->cacheex.lg_only_in_tab;
				if(!lgonly_tab->nfilts)
					lgonly_tab = &cfg.cacheex_lg_only_in_tab;
			}
			else
			{
				return;
			}
			
			char *cx_aio_ftab;
			cx_aio_ftab = cxaio_ftab_to_buf(lgonly_tab);
			if(strlen(cx_aio_ftab) > 0 && cx_aio_ftab[0] != '\0')
			{
				size += strlen(cx_aio_ftab) * sizeof(char);
				
				// payload-size
				i2b_buf(2, strlen(cx_aio_ftab), payload + i);
				i += 2;

				// filter counter
				payload[i] = lgonly_tab->nfilts;
				i += 1;

				for(j=0; j<strlen(cx_aio_ftab); j+=2)
				{
					payload[i] = (gethexval(cx_aio_ftab[j]) << 4) | gethexval(cx_aio_ftab[j + 1]);
					i++;
				}
			}
			
			if(size < 32)
				size = 32;

			NULLFREE(cx_aio_ftab);
			break;
		default:
			return;
	}

	uint8_t buf[size];
	memset(buf, 0, sizeof(buf));
	buf[0] = 0x42;	// camd35_cacheex_feature_trigger
	
	buf[1] = (size - 20) & 0xFF;
	buf[2] = (size - 20) >> 8;
	
	uint8_t *ofs = buf + 20;
	memcpy(ofs, payload, size - 20);

	camd35_send_without_timeout(cl, buf, size-20); //send adds +20
}

void camd35_cacheex_feature_request_save(struct s_client *cl, uint8_t *buf)
{
	int32_t field = b2i(2, (buf+20));

	if(cl->typ == 'c' && (cl->account->cacheex.mode == 2 || cl->account->cacheex.mode == 1))
	{
		cl->account->cacheex.feature_bitfield = field;
		// flag 32 => aio-version
		if(cl->account->cacheex.feature_bitfield & 32)
		{
			camd35_cacheex_feature_trigger(cl, 32, 2);
		}
	}

	if(cl->typ == 'p' && cl->reader->cacheex.mode == 3)
	{
		cl->reader->cacheex.feature_bitfield = field;
		// flag 32 => aio-version
		if(cl->reader->cacheex.feature_bitfield & 32)
		{
			camd35_cacheex_feature_trigger(cl, 32, 3);
		}
	}

	if(cl->typ == 'c' && cl->account->cacheex.mode == 3)
	{
		struct s_auth *acc = cl->account;
		if(acc)
		{
			acc->cacheex.feature_bitfield = field;
			// process feature-specific actions based on feature_bitfield received
			
			// flag 1 => set localgenerated only flag
			if(acc->cacheex.feature_bitfield & 1)
			{
				camd35_cacheex_feature_trigger(cl, 1, 3);
			}
			// flag 2 => set localgenerated only caids flag
			if(acc->cacheex.feature_bitfield & 2 && !(acc->cacheex.feature_bitfield & 64))
			{
				camd35_cacheex_feature_trigger(cl, 2, 3);
			}
			// flag 4 => set cacheex_ecm_filter (extended)
			if(acc->cacheex.feature_bitfield & 4)
			{
				camd35_cacheex_feature_trigger(cl, 4, 3);
			}
			// flag 8 => np push after caids
			if(acc->cacheex.feature_bitfield & 8)
			{
				camd35_cacheex_feature_trigger(cl, 8, 3);
			}
			// flag 16 => maxhop
			if(acc->cacheex.feature_bitfield & 16)
			{
				camd35_cacheex_feature_trigger(cl, 16, 3);
			}
			// flag 32 => aio-version
			if(acc->cacheex.feature_bitfield & 32)
			{
				camd35_cacheex_feature_trigger(cl, 32, 3);
			}
			// flag 64 => lg_only_tab
			if(acc->cacheex.feature_bitfield & 64)
			{
				camd35_cacheex_feature_trigger(cl, 64, 3);
			}
		}
		else
		{
			cs_log_dbg(D_CACHEEX, "feature_bitfield save failed - cl, %s", username(cl));
		}
	}
	else if(cl->typ == 'p' && (cl->reader->cacheex.mode == 2 || cl->reader->cacheex.mode == 1))
	{
		struct s_reader *rdr = cl->reader;
		if(rdr)
		{
			rdr->cacheex.feature_bitfield = field;
			// process feature-specific actions

			// flag 1 => set localgenerated_only; cause of rdr->cacheex.localgenerated_only_in is set
			if(rdr->cacheex.feature_bitfield & 1)
			{
				camd35_cacheex_feature_trigger(cl, 1, 2);
			}
			
			// flag 2 => set lg_only_tab; cause of rdr->cacheex.lg_only_in_tab is set
			if(rdr->cacheex.feature_bitfield & 2 && !(rdr->cacheex.feature_bitfield & 64))
			{
				camd35_cacheex_feature_trigger(cl, 2, 2);
			}

			// // flag 4 => set cacheex_ecm_filter (extended)
			if(rdr->cacheex.feature_bitfield & 4)
			{
				camd35_cacheex_feature_trigger(cl, 4, 2);
			}

			// flag 8 => no push after caids
			if(rdr->cacheex.feature_bitfield & 8)
			{
				camd35_cacheex_feature_trigger(cl, 8, 2);
			}
			// flag 16 => maxhop
			if(rdr->cacheex.feature_bitfield & 16)
			{
				camd35_cacheex_feature_trigger(cl, 16, 2);
			}
			// flag 32 => aio-version
			if(rdr->cacheex.feature_bitfield & 32)
			{
				camd35_cacheex_feature_trigger(cl, 32, 2);
			}
			// flag 64 => lg_only_tab
			if(rdr->cacheex.feature_bitfield & 64)
			{
				camd35_cacheex_feature_trigger(cl, 64, 2);
			}
		}
		else
		{
			cs_log_dbg(D_CACHEEX, "feature_bitfield save failed - rdr, %s", username(cl));
		}
	}
}

void camd35_cacheex_feature_request(struct s_client *cl)
{
	int i = 20;

	uint8_t buf[32];
	memset(buf, 0, sizeof(buf));
	buf[0] = 0x40;
	buf[1] = 12;
	buf[2] = 0;

	i2b_buf(2, CACHEEX_FEATURES, buf + i); // set feature-list here
	i += 2;

	camd35_send_without_timeout(cl, buf, 12); //send adds +20
}

void camd35_cacheex_feature_request_reply(struct s_client *cl, uint8_t *buf)
{
	camd35_cacheex_feature_request_save(cl, buf);
	int i = 20;

	uint8_t rbuf[32];
	memset(rbuf, 0, sizeof(rbuf));
	rbuf[0] = 0x41;
	rbuf[1] = 12;
	rbuf[2] = 0;
	
	i2b_buf(2, CACHEEX_FEATURES, rbuf + i);
	i += 2;

	camd35_send_without_timeout(cl, rbuf, 12); //send adds +20
}



/**
 * send push filter
 */
void camd35_cacheex_send_push_filter(struct s_client *cl, uint8_t mode)
{
	struct s_reader *rdr = cl->reader;
	int i = 20, j;
	CECSPVALUETAB *filter;
	//maximum size: 20+255
	uint8_t buf[20+242];
	memset(buf, 0, sizeof(buf));
	buf[0] = 0x3c;
	buf[1] = 0xf2;

	//mode==2 send filters from rdr
	if(mode == 2 && rdr)
	{
		filter = &rdr->cacheex.filter_caidtab;
		// if not set, use global settings
		if(rdr->cacheex.filter_caidtab.cevnum == 0 && cfg.cacheex_filter_caidtab.cevnum > 0)
			filter = &cfg.cacheex_filter_caidtab;
	}
	//mode==3 send filters from acc
	else if(mode == 3 && cl->typ == 'c' && cl->account)
	{
		filter = &cl->account->cacheex.filter_caidtab;
		// if not set, use global settings
		if(cl->account->cacheex.filter_caidtab.cevnum == 0 && cfg.cacheex_filter_caidtab.cevnum > 0)
			filter = &cfg.cacheex_filter_caidtab;
	}
	else {
		return;
	}

	i2b_buf(2, filter->cevnum, buf + i);
	i += 2;

	int32_t max_filters = 15;
	for(j=0; j<max_filters; j++)
	{
		if(filter->cevnum > j){
			CECSPVALUETAB_DATA *d = &filter->cevdata[j];
			i2b_buf(4, d->caid, buf + i);
		}
		i += 4;
	}

	for(j=0; j<max_filters; j++)
	{
		if(filter->cevnum > j){
			CECSPVALUETAB_DATA *d = &filter->cevdata[j];
			i2b_buf(4, d->cmask, buf + i);
		}
		i += 4;
	}

	for(j=0; j<max_filters; j++)
	{
		if(filter->cevnum > j){
			CECSPVALUETAB_DATA *d = &filter->cevdata[j];
			i2b_buf(4, d->prid, buf + i);
		}
		i += 4;
	}

	for(j=0; j<max_filters; j++)
	{
		if(filter->cevnum > j){
			CECSPVALUETAB_DATA *d = &filter->cevdata[j];
			i2b_buf(4, d->srvid, buf + i);
		}
		i += 4;
	}

	cs_log_dbg(D_CACHEEX, "cacheex: sending push filter request to %s", username(cl));
	camd35_send_without_timeout(cl, buf, 242); //send adds +20
}

/**
 * store received push filter
 */
static void camd35_cacheex_push_filter(struct s_client *cl, uint8_t *buf, uint8_t mode)
{
	struct s_reader *rdr = cl->reader;
	int i = 20, j;
	int32_t caid, cmask, provid, srvid;
	CECSPVALUETAB *filter;

	//mode==2 write filters to acc
	if(mode == 2 && cl->typ == 'c' && cl->account && cl->account->cacheex.mode == 2
		&& cl->account->cacheex.allow_filter == 1)
	{
		filter = &cl->account->cacheex.filter_caidtab;
	}
	//mode==3 write filters to rdr
	else if(mode == 3 && rdr && rdr->cacheex.allow_filter == 1)
	{
		filter = &rdr->cacheex.filter_caidtab;
	}
	else {
		return;
	}

	cecspvaluetab_clear(filter);
	i += 2;

	int32_t max_filters = 15;
	for(j=0; j<max_filters; j++)
	{
		caid = b2i(4, buf + i);
		if(caid > 0){
			CECSPVALUETAB_DATA d;
			memset(&d, 0, sizeof(d));
			d.caid = b2i(4, buf + i);
			cecspvaluetab_add(filter, &d);
		}
		i += 4;
	}

	for(j=0; j<max_filters; j++)
	{
		cmask = b2i(4, buf + i);
		if(j<filter->cevnum){
			CECSPVALUETAB_DATA *d = &filter->cevdata[j];
			d->cmask = cmask;
		}
		i += 4;
	}

	for(j=0; j<max_filters; j++)
	{
		provid = b2i(4, buf + i);
		if(j<filter->cevnum){
			CECSPVALUETAB_DATA *d = &filter->cevdata[j];
			d->prid = provid;
		}
		i += 4;
	}

	for(j=0; j<max_filters; j++)
	{
		srvid = b2i(4, buf + i);
		if(j<filter->cevnum){
			CECSPVALUETAB_DATA *d = &filter->cevdata[j];
			d->srvid = srvid;
		}
		i += 4;
	}

	cs_log_dbg(D_CACHEEX, "cacheex: received push filter request from %s", username(cl));
}

static int32_t camd35_cacheex_push_chk(struct s_client *cl, ECM_REQUEST *er)
{
	if(
			ll_count(er->csp_lastnodes) >= cacheex_maxhop(cl)	    												// check max 10 nodes to push
		&& (!er->localgenerated || (er->localgenerated && (ll_count(er->csp_lastnodes) >= cacheex_maxhop_lg(cl))))	// check maxhop_lg if cw is lg-flagged
	)
	{
		cs_log_dbg(D_CACHEEX, "cacheex: nodelist reached %d nodes(non-lg) or reached %d nodes(lg), no push", cacheex_maxhop(cl), cacheex_maxhop_lg(cl));
		return 0;
	}

	if(cl->reader)
	{
		if(!cl->reader->tcp_connected)
		{
			cs_log_dbg(D_CACHEEX, "cacheex: not connected %s -> no push", username(cl));
			return 0;
		}
	}

	//if(chk_is_null_nodeid(remote_node,8)){
	if(!cl->ncd_skey[8])
	{
		cs_log_dbg(D_CACHEEX, "cacheex: NO peer_node_id got yet, skip!");
		return 0;
	}

	uint8_t *remote_node = cl->ncd_skey; //it is sended by reader(mode 2) or client (mode 3) each 30s using keepalive msgs

	//search existing peer nodes:
	LL_LOCKITER *li = ll_li_create(er->csp_lastnodes, 0);
	uint8_t *node;
	while((node = ll_li_next(li)))
	{
		cs_log_dbg(D_CACHEEX, "cacheex: check node %" PRIu64 "X == %" PRIu64 "X ?", cacheex_node_id(node), cacheex_node_id(remote_node));
		if(memcmp(node, remote_node, 8) == 0)
		{
			break;
		}
	}
	ll_li_destroy(li);

	//node found, so we got it from there, do not push:
	if(node)
	{
		cs_log_dbg(D_CACHEEX,
					  "cacheex: node %" PRIu64 "X found in list => skip push!", cacheex_node_id(node));
		return 0;
	}

	//check if cw is already pushed
	if(check_is_pushed(er->cw_cache, cl))
		{ return 0; }

	cs_log_dbg(D_CACHEEX, "cacheex: push ok %" PRIu64 "X to %" PRIu64 "X %s", cacheex_node_id(camd35_node_id), cacheex_node_id(remote_node), username(cl));

	return 1;
}

static int32_t camd35_cacheex_push_out(struct s_client *cl, struct ecm_request_t *er)
{
	int8_t rc = (er->rc < E_NOTFOUND) ? E_FOUND : er->rc;
	if(rc != E_FOUND && rc != E_UNHANDLED) { return -1; }  //Maybe later we could support other rcs

	//E_FOUND     : we have the CW,
	//E_UNHANDLED : incoming ECM request

	if(cl->reader)
	{
		if(!camd35_tcp_connect(cl))
		{
			cs_log_dbg(D_CACHEEX, "cacheex: not connected %s -> no push", username(cl));
			return (-1);
		}
	}

	uint32_t size = sizeof(er->ecmd5) + sizeof(er->csp_hash) + sizeof(er->cw) + sizeof(uint8_t) +
					(ll_count(er->csp_lastnodes) + 1) * 8 + sizeof(uint8_t);
	uint8_t *buf;
	if(!cs_malloc(&buf, size + 20))  //camd35_send() adds +20
		{ return -1; }

	buf[0] = 0x3f; //New Command: Cache-push
	buf[1] = size & 0xff;
	buf[2] = size >> 8;
	buf[3] = rc;

	i2b_buf(2, er->srvid, buf + 8);
	i2b_buf(2, er->caid, buf + 10);
	i2b_buf(4, er->prid, buf + 12);
	//i2b_buf(2, er->idx, buf + 16); // Not relevant...?

	if(er->cwc_cycletime && er->cwc_next_cw_cycle < 2)
	{
		buf[18] = er->cwc_cycletime; // contains cwc stage3 cycletime
		if(er->cwc_next_cw_cycle == 1)
		{ buf[18] = (buf[18] | 0x80); } // set bit 8 to high

		if(cl->typ == 'c' && cl->account && cl->account->cacheex.mode)
			{ cl->account->cwc_info++; }
		else if((cl->typ == 'p' || cl->typ == 'r') && (cl->reader && cl->reader->cacheex.mode))
			{ cl->cwc_info++; }

		cs_log_dbg(D_CWC, "CWC (CE) push to %s cycletime: %isek - nextcwcycle: CW%i for %04X@%06X:%04X", username(cl), er->cwc_cycletime, er->cwc_next_cw_cycle, er->caid, er->prid, er->srvid);
	}

	buf[19] = er->ecm[0] != 0x80 && er->ecm[0] != 0x81 ? 0 : er->ecm[0];

	uint8_t *ofs = buf + 20;

	//write oscam ecmd5:
	memcpy(ofs, er->ecmd5, sizeof(er->ecmd5)); //16
	ofs += sizeof(er->ecmd5);

	//write csp hashcode:
	i2b_buf(4, CSP_HASH_SWAP(er->csp_hash), ofs);
	ofs += 4;

	//write cw:
	memcpy(ofs, er->cw, sizeof(er->cw)); //16
	ofs += sizeof(er->cw);

	//write node count:
	*ofs = ll_count(er->csp_lastnodes) + 1;
	ofs++;

	//write own node:
	memcpy(ofs, camd35_node_id, 8);
	ofs += 8;

	//write other nodes:
	LL_LOCKITER *li = ll_li_create(er->csp_lastnodes, 0);
	uint8_t *node;
	while((node = ll_li_next(li)))
	{
		memcpy(ofs, node, 8);
		ofs += 8;
	}
	ll_li_destroy(li);

	// add localgenerated cw-flag
	if(er->localgenerated)
	{
		*ofs = 1;
	}
	else
	{
		*ofs = 0xFF;
	}
	ofs += 1;

	int32_t res = camd35_send(cl, buf, size);
	NULLFREE(buf);
	return res;
}

static void camd35_cacheex_push_in(struct s_client *cl, uint8_t *buf)
{
	int8_t rc = buf[3];
	if(rc != E_FOUND && rc != E_UNHANDLED)  //Maybe later we could support other rcs
		{ return; }

	ECM_REQUEST *er;
	uint16_t size = buf[1] | (buf[2] << 8);
	if(size < sizeof(er->ecmd5) + sizeof(er->csp_hash) + sizeof(er->cw))
	{
		cs_log_dbg(D_CACHEEX, "cacheex: %s received old cash-push format! data ignored!", username(cl));
		return;
	}

	if(!(er = get_ecmtask()))
		{ return; }

	er->srvid = b2i(2, buf + 8);
	er->caid = b2i(2, buf + 10);
	er->prid = b2i(4, buf + 12);
	er->pid  = b2i(2, buf + 16);
	er->ecm[0] = buf[19]!=0x80 && buf[19]!=0x81 ? 0 : buf[19]; //odd/even byte, usefull to send it over CSP and to check cw for swapping
	er->rc = rc;

	er->ecmlen = 0;

	if(buf[18])
	{
		if(buf[18] & (0x01 << 7))
		{
			er->cwc_cycletime = (buf[18] & 0x7F); // remove bit 8 to get cycletime
			er->cwc_next_cw_cycle = 1;
		}
		else
		{
			er->cwc_cycletime = buf[18];
			er->cwc_next_cw_cycle = 0;
		}
	}

	uint8_t *ofs = buf + 20;

	//Read ecmd5
	memcpy(er->ecmd5, ofs, sizeof(er->ecmd5)); //16
	ofs += sizeof(er->ecmd5);

	if(!check_cacheex_filter(cl, er))
	{
		return; 
	}

	// check incoming cache
	if(check_client(cl) && cl->typ == 'p' && cl->reader && cl->reader->cacheex.mode == 2
		&& 	(		(cl->reader->cacheex.filter_caidtab.cevnum > 0 && !chk_csp_ctab(er, &cl->reader->cacheex.filter_caidtab)) // reader cacheex_ecm_filter not matching if set
				|| 	(cl->reader->cacheex.filter_caidtab.cevnum == 0 && (cl->reader->cacheex.feature_bitfield & 4) && cfg.cacheex_filter_caidtab_aio.cevnum > 0 && !chk_csp_ctab(er, &cfg.cacheex_filter_caidtab_aio)) // global cacheex_ecm_filter_aio not matching if set
				|| 	(cl->reader->cacheex.filter_caidtab.cevnum == 0 && cfg.cacheex_filter_caidtab_aio.cevnum == 0 && cfg.cacheex_filter_caidtab.cevnum > 0 && !chk_csp_ctab(er, &cfg.cacheex_filter_caidtab)) // global cacheex_ecm_filter not matching if set
			)
	)
	{
		cs_log_dbg(D_CACHEEX, "cacheex: received cache not matching cacheex_ecm_filter => pushing filter again");
		camd35_cacheex_send_push_filter(cl, 2);	// get cache != cacheex_ecm_filter, send filter again - remote restarted
		if(cl->reader->cacheex.feature_bitfield & 4)
			camd35_cacheex_feature_trigger(cl, 4, 2);
		free_push_in_ecm(er);
		return;
	}

	if(check_client(cl) && cl->typ == 'c' && cl->account && cl->account->cacheex.mode == 3
		&& 	(		(cl->account->cacheex.filter_caidtab.cevnum > 0 && !chk_csp_ctab(er, &cl->account->cacheex.filter_caidtab)) // account cacheex_ecm_filter not matching if set
				|| 	(cl->account->cacheex.filter_caidtab.cevnum == 0 && (cl->account->cacheex.feature_bitfield & 4) && cfg.cacheex_filter_caidtab_aio.cevnum > 0 && !chk_csp_ctab(er, &cfg.cacheex_filter_caidtab_aio)) // global cacheex_ecm_filter_aio not matching if set
				|| 	(cl->account->cacheex.filter_caidtab.cevnum == 0 && cfg.cacheex_filter_caidtab_aio.cevnum == 0 && cfg.cacheex_filter_caidtab.cevnum > 0 && !chk_csp_ctab(er, &cfg.cacheex_filter_caidtab)) // global cacheex_ecm_filter not matching if set
			)
	)
	{
		cs_log_dbg(D_CACHEEX, "cacheex: received cache not matching cacheex_ecm_filter => pushing filter again");
		camd35_cacheex_send_push_filter(cl, 3); // get cache != cacheex_ecm_filter, send filter again - remote restarted
		if(cl->account->cacheex.feature_bitfield & 4)
			camd35_cacheex_feature_trigger(cl, 4, 3);
		free_push_in_ecm(er);
		return;
	}

	//Read csp_hash:
	er->csp_hash = CSP_HASH_SWAP(b2i(4, ofs));
	ofs += 4;

	//Read cw:
	memcpy(er->cw, ofs, sizeof(er->cw)); //16
	ofs += sizeof(er->cw);

	//Check auf neues Format:
	uint8_t *data;
	if(size > (sizeof(er->ecmd5) + sizeof(er->csp_hash) + sizeof(er->cw)))
	{

		//Read lastnodes:
		uint8_t count = *ofs;
		ofs++;

		cs_log_dbg(D_CACHEEX, "cacheex: received %d nodes %s", (int32_t)count, username(cl));
		if (er){
			er->csp_lastnodes = ll_create("csp_lastnodes");
		}
		while(count)
		{
			if(!cs_malloc(&data, 8))
				{ break; }
			memcpy(data, ofs, 8);
			ofs += 8;
			ll_append(er->csp_lastnodes, data);
			count--;
			cs_log_dbg(D_CACHEEX, "cacheex: received node %" PRIu64 "X %s", cacheex_node_id(data), username(cl));
		}

		// check byte after nodelist for "localgenerated CW"-flag
		if(b2i(1, ofs) == 1)
		{
			er->localgenerated = 1;
			cs_log_dbg(D_CACHEEX, "cacheex: received ECM with localgenerated flag %04X@%06X:%04X %s", er->caid, er->prid, er->srvid, username(cl));
			
			//check max nodes for lg flagged cw:
			if(ll_count(er->csp_lastnodes) > cacheex_maxhop_lg(cl))
			{
				cs_log_dbg(D_CACHEEX, "cacheex: received (lg) %d nodes (max=%d), ignored! %s", ll_count(er->csp_lastnodes), cacheex_maxhop_lg(cl), username(cl));
				free_push_in_ecm(er);
				return;
			}
		}
		// without localgenerated flag
		else
		{
			//check max nodes:
			if(ll_count(er->csp_lastnodes) > cacheex_maxhop(cl))
			{
				cs_log_dbg(D_CACHEEX, "cacheex: received %d nodes (max=%d), ignored! %s", ll_count(er->csp_lastnodes), cacheex_maxhop(cl), username(cl));
				free_push_in_ecm(er);
				return;
			}

			if(
				(cl->typ == 'p' && cl->reader && cl->reader->cacheex.mode == 2 && !chk_srvid_localgenerated_only_exception(er) // cx1&2
					&& (
						// !aio
						(cl->cacheex_aio_checked && !cl->reader->cacheex.feature_bitfield
							&& (
								!cfg.cacheex_lg_only_in_aio_only && !cl->reader->cacheex.lg_only_in_aio_only 
								&& (cfg.cacheex_localgenerated_only_in || cl->reader->cacheex.localgenerated_only_in || chk_lg_only(er, &cl->reader->cacheex.lg_only_in_tab) || chk_lg_only(er, &cfg.cacheex_lg_only_in_tab))
							)
						)
						||
						// aio
						(cl->cacheex_aio_checked && cl->reader->cacheex.feature_bitfield
							&& (
								cfg.cacheex_localgenerated_only_in || cl->reader->cacheex.localgenerated_only_in || chk_lg_only(er, &cl->reader->cacheex.lg_only_in_tab) || chk_lg_only(er, &cfg.cacheex_lg_only_in_tab)
							)
						)
					)
				)
				||
				(cl->typ == 'c' && cl->account && cl->account->cacheex.mode == 3 && !chk_srvid_localgenerated_only_exception(er) // cx3
					&& (
						// !aio
						(cl->cacheex_aio_checked && !cl->account->cacheex.feature_bitfield
							&& (
								!cfg.cacheex_lg_only_in_aio_only && !cl->account->cacheex.lg_only_in_aio_only 
								&& (cfg.cacheex_localgenerated_only_in || cl->account->cacheex.localgenerated_only_in || chk_lg_only(er, &cl->account->cacheex.lg_only_in_tab) || chk_lg_only(er, &cfg.cacheex_lg_only_in_tab))
							)
						)
						||
						// aio
						(cl->cacheex_aio_checked && cl->account->cacheex.feature_bitfield
							&& (
								cfg.cacheex_localgenerated_only_in || cl->account->cacheex.localgenerated_only_in || chk_lg_only(er, &cl->account->cacheex.lg_only_in_tab) || chk_lg_only(er, &cfg.cacheex_lg_only_in_tab)
							)
						)
					)
				)
			)
			{
				cs_log_dbg(D_CACHEEX, "cacheex: drop ECM without localgenerated flag %04X@%06X:%04X %s", er->caid, er->prid, er->srvid, username(cl));
				free_push_in_ecm(er);
				return;
			}
		}
	}
	else
	{
		cs_log_dbg(D_CACHEEX, "cacheex: received old cachex from %s", username(cl));
		er->csp_lastnodes = ll_create("csp_lastnodes");
	}

	//store remote node id if we got one. The remote node is the first node in the node list
	data = ll_has_elements(er->csp_lastnodes);
	if(data && !cl->ncd_skey[8])    //Ok, this is tricky, we use newcamd key storage for saving the remote node
	{
		memcpy(cl->ncd_skey, data, 8);
		cl->ncd_skey[8] = 1; //Mark as valid node
	}
	cs_log_dbg(D_CACHEEX, "cacheex: received cacheex from remote node id %" PRIu64 "X", cacheex_node_id(cl->ncd_skey));

	//for compatibility: add peer node if no node received (not working now, maybe later):
	if(!ll_count(er->csp_lastnodes) && cl->ncd_skey[8])
	{
		if(!cs_malloc(&data, 8))
		{ 
			free_push_in_ecm(er);
			return;
		}
		memcpy(data, cl->ncd_skey, 8);
		ll_append(er->csp_lastnodes, data);
		cs_log_dbg(D_CACHEEX, "cacheex: added missing remote node id %" PRIu64 "X", cacheex_node_id(data));
	}

	if (er->cwc_cycletime && er->cwc_next_cw_cycle < 2)
	{
		if(cl->typ == 'c' && cl->account && cl->account->cacheex.mode)
			{ cl->account->cwc_info++; }
		else if((cl->typ == 'p' || cl->typ == 'r') && (cl->reader && cl->reader->cacheex.mode))
			{ cl->cwc_info++; }
		cs_log_dbg(D_CWC, "CWC (CE) received from %s cycletime: %isek - nextcwcycle: CW%i for %04X@%06X:%04X", username(cl), er->cwc_cycletime, er->cwc_next_cw_cycle, er->caid, er->prid, er->srvid);
	}

	cacheex_add_to_cache(cl, er);
}

void camd35_cacheex_recv_ce1_cwc_info(struct s_client *cl, uint8_t *buf, int32_t idx)
{
	if(!(buf[0] == 0x01 && buf[18] < 0xFF && buf[18] > 0x00)) // cwc info ; normal camd3 ecms send 0xFF but we need no cycletime of 255 ;)
		return;

	ECM_REQUEST *er = NULL;
	int32_t i;

	for(i = 0; i < cfg.max_pending; i++)
	{
		if (cl->ecmtask[i].idx == idx)
		{
			er = &cl->ecmtask[i];
			break;
		}
	}

	if(!er)
	{ return; }

	int8_t rc = buf[3];
	if(rc != E_FOUND)
		{ return; }

	if(buf[18])
	{
		if(buf[18] & (0x01 << 7))
		{
			er->cwc_cycletime = (buf[18] & 0x7F); // remove bit 8 to get cycletime
			er->parent->cwc_cycletime = er->cwc_cycletime;
			er->cwc_next_cw_cycle = 1;
			er->parent->cwc_next_cw_cycle = er->cwc_next_cw_cycle;
		}
		else
		{
			er->cwc_cycletime = buf[18];
			er->parent->cwc_cycletime = er->cwc_cycletime;
			er->cwc_next_cw_cycle = 0;
			er->parent->cwc_next_cw_cycle = er->cwc_next_cw_cycle;
		}
	}

	if(cl->typ == 'c' && cl->account && cl->account->cacheex.mode)
		{ cl->account->cwc_info++; }
	else if((cl->typ == 'p' || cl->typ == 'r') && (cl->reader && cl->reader->cacheex.mode))
		{ cl->cwc_info++; }

	cs_log_dbg(D_CWC, "CWC (CE1) received from %s cycletime: %isek - nextcwcycle: CW%i for %04X@%06X:%04X", username(cl), er->cwc_cycletime, er->cwc_next_cw_cycle, er->caid, er->prid, er->srvid);

}


/**
 * when a server client connects
 */
static void camd35_server_client_init(struct s_client *cl)
{
	if(!cl->init_done)
	{
		cl->cacheex_needfilter = 1;
	}
}

/**
 * store received remote id
 */
static void camd35_cacheex_push_receive_remote_id(struct s_client *cl, uint8_t *buf)
{

	memcpy(cl->ncd_skey, buf + 20, 8);
	cl->ncd_skey[8] = 1;
	cs_log_dbg(D_CACHEEX, "cacheex: received id answer from %s: %" PRIu64 "X", username(cl), cacheex_node_id(cl->ncd_skey));
}


void camd35_cacheex_init_dcw(struct s_client *client, ECM_REQUEST *er)
{
	uint8_t *buf = er->src_data; // get orig request

	if(((client->typ == 'c' && client->account && client->account->cacheex.mode)
		|| ((client->typ == 'p' || client->typ == 'r') && (client->reader && client->reader->cacheex.mode)))
		&& er->cwc_cycletime && er->cwc_next_cw_cycle < 2)  // ce1
	{
		buf[18] = er->cwc_cycletime; // contains cwc stage3 cycletime
		if(er->cwc_next_cw_cycle == 1)
			{ buf[18] = (buf[18] | 0x80); } // set bit 8 to high
		if(client->typ == 'c' && client->account && client->account->cacheex.mode)
			{ client->account->cwc_info++; }
		else if((client->typ == 'p' || client->typ == 'r') && (client->reader && client->reader->cacheex.mode))
			{ client->cwc_info++; }
		cs_log_dbg(D_CWC, "CWC (CE1) push to %s cycletime: %isek - nextcwcycle: CW%i for %04X@%06X:%04X", username(client), er->cwc_cycletime, er->cwc_next_cw_cycle, er->caid, er->prid, er->srvid);
		buf[19] = er->ecm[0];
	}
}

/**
 * send own id
 */
void camd35_cacheex_push_send_own_id(struct s_client *cl, uint8_t *mbuf)
{
	uint8_t rbuf[32]; //minimal size
	if(!cl->crypted) { return; }
	cs_log_dbg(D_CACHEEX, "cacheex: received id request from node %" PRIu64 "X %s", cacheex_node_id(mbuf + 20), username(cl));
	memset(rbuf, 0, sizeof(rbuf));
	rbuf[0] = 0x3e;
	rbuf[1] = 12;
	rbuf[2] = 0;
	memcpy(rbuf + 20, camd35_node_id, 8);
	cs_log_dbg(D_CACHEEX, "cacheex: sending own id %" PRIu64 "X request %s", cacheex_node_id(camd35_node_id), username(cl));
	camd35_send(cl, rbuf, 12); //send adds +20
}

bool camd35_cacheex_server(struct s_client *client, uint8_t *mbuf)
{
	switch(mbuf[0])
	{
	case 0x3c:  // Cache-push filter request
		if(client->account && client->account->cacheex.mode==2){
			camd35_cacheex_push_filter(client, mbuf, 2);
		}
		break;
	case 0x3d:  // Cache-push id request
		camd35_cacheex_push_receive_remote_id(client, mbuf); //reader send request id with its nodeid, so we save it!
		camd35_cacheex_push_send_own_id(client, mbuf);
		if(client->cacheex_needfilter && client->account && client->account->cacheex.mode==3){
			camd35_cacheex_send_push_filter(client, 3);
			client->cacheex_needfilter = 0;
		}
		if(!client->cacheex_aio_checked && ((client->account && client->account->cacheex.mode > 0) || (client->reader && client->reader->cacheex.mode > 0)))
		{
			camd35_cacheex_feature_request(client);
			client->cacheex_aio_checked = 1;
		}
		break;
	case 0x3e:  // Cache-push id answer
		camd35_cacheex_push_receive_remote_id(client, mbuf);
		break;
	case 0x3f:  // Cache-push
		camd35_cacheex_push_in(client, mbuf);
		break;
	case 0x40:	// cacheex-features request
		camd35_cacheex_feature_request_reply(client, mbuf);
		break;
	case 0x41:	// cacheex-features answer
		camd35_cacheex_feature_request_save(client, mbuf);		
		break;
	case 0x42:	// cacheex-feature trigger in
		camd35_cacheex_feature_trigger_in(client, mbuf);
		break;
	default:
		return 0; // Not processed by cacheex
	}
	return 1; // Processed by cacheex
}

bool camd35_cacheex_recv_chk(struct s_client *client, uint8_t *buf)
{
	struct s_reader *rdr = client->reader;
	switch(buf[0])
	{
	case 0x3c:    // Cache-push filter request
		if(rdr->cacheex.mode==3){
			camd35_cacheex_push_filter(client, buf, 3);
		}
		break;
	case 0x3d:    // Cache-push id request
		camd35_cacheex_push_receive_remote_id(client, buf); //client send request id with its nodeid, so we save it!
		camd35_cacheex_push_send_own_id(client, buf);
		break;
	case 0x3e:     // Cache-push id answer
		camd35_cacheex_push_receive_remote_id(client, buf);
		if(!client->cacheex_aio_checked && ((client->account && client->account->cacheex.mode > 0) || (client->reader && client->reader->cacheex.mode > 0)))
		{
			camd35_cacheex_feature_request(client);
			client->cacheex_aio_checked = 1;
		}
		break;
	case 0x3f:    //cache-push
		camd35_cacheex_push_in(client, buf);
		break;
	case 0x40:	  // cacheex-features request
		camd35_cacheex_feature_request_reply(client, buf);
		break;		
	case 0x41:	// cacheex-features answer
		camd35_cacheex_feature_request_save(client, buf);
		break;
	case 0x42:	// cacheex-feature trigger in
		camd35_cacheex_feature_trigger_in(client, buf);
		break;
	default:
		return 0; // Not processed by cacheex
	}
	return 1; // Processed by cacheex
}

/**
 * request remote id
 */
void camd35_cacheex_push_request_remote_id(struct s_client *cl)
{
	uint8_t rbuf[32];//minimal size
	memset(rbuf, 0, sizeof(rbuf));
	rbuf[0] = 0x3d;
	rbuf[1] = 12;
	rbuf[2] = 0;
	memcpy(rbuf + 20, camd35_node_id, 8);
	cs_log_dbg(D_CACHEEX, "cacheex: sending id request to %s", username(cl));
	camd35_send(cl, rbuf, 12); //send adds +20
}

void camd35_cacheex_module_init(struct s_module *ph)
{
	ph->c_cache_push = camd35_cacheex_push_out;
	ph->c_cache_push_chk = camd35_cacheex_push_chk;
	ph->s_init = camd35_server_client_init;
}

#endif
