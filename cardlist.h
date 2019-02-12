#ifndef _CSCTAPI_CARDLIST_H_
#define _CSCTAPI_CARDLIST_H_
struct atrlist{ int found; int ishd03; int badcard; int ishd04; char providername[32]; char atr[80]; };
void findatr(struct s_reader *reader);
#endif
