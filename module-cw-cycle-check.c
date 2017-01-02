#define MODULE_LOG_PREFIX "cwccheck"

#include "globals.h"
#ifdef CW_CYCLE_CHECK

#include "module-cw-cycle-check.h"
#include "oscam-chk.h"
#include "oscam-client.h"
#include "oscam-ecm.h"
#include "oscam-lock.h"
#include "oscam-string.h"
#include "oscam-cache.h"
#include "oscam-time.h"
#include "oscam-garbage.h"

struct s_cwc_md5
{
	uchar           md5[CS_ECMSTORESIZE];
	uint32_t        csp_hash;
	uchar           cw[16];
};

struct s_cw_cycle_check
{
	uchar           cw[16];
	time_t          time;
	time_t          locktime; // lock in learning
	struct timeb    locktime1;
	uint16_t        caid;
	uint16_t        sid;
	uint16_t        chid;
	uint32_t        provid;
	int16_t         ecmlen;
	int8_t          stage;
	int32_t         cycletime;
	int32_t         dyncycletime;
	int8_t          nextcyclecw;
	struct s_cwc_md5    ecm_md5[15]; // max 15 old ecm md5 /csp-hashs
	int8_t          cwc_hist_entry;
	int8_t			stage4_repeat;
//	struct s_cw_cycle_check *prev;
//	struct s_cw_cycle_check *next;
};

static int32_t deltime;

pthread_mutex_t cwcycle_lock1;   
pthread_mutex_t cwcycle_lock2;   
pthread_mutex_t cwcycle_lock3;   
pthread_mutex_t cwcycle_lock4;   
pthread_mutex_t cwcycle_lock5;   
pthread_mutex_t cwcycle_lock6;   
pthread_mutex_t cwcycle_lock7;   
pthread_mutex_t cwcycle_lock8;   
pthread_mutex_t cwcycle_lock9;   
pthread_mutex_t cwcycle_lock10;  
pthread_mutex_t cwcycle_lock11;  
pthread_mutex_t cwcycle_lock12;  
pthread_mutex_t cwcycle_lock13;  
pthread_mutex_t cwcycle_lock14;  
pthread_mutex_t cwcycle_lock15;  
pthread_mutex_t cwcycle_lock16;  
pthread_mutex_t cwcycle_lock17;  
pthread_mutex_t cwcycle_lock18;  
pthread_mutex_t cwcycle_lock19;  
pthread_mutex_t cwcycle_lock20;  
pthread_mutex_t cwcycle_lock21;  
pthread_mutex_t cwcycle_lock22;  
pthread_mutex_t cwcycle_lock23;  
pthread_mutex_t cwcycle_lock24;  
pthread_mutex_t cwcycle_lock25;  
pthread_mutex_t cwcycle_lock26;  
pthread_mutex_t cwcycle_lock27;  
pthread_mutex_t cwcycle_lock28;  
pthread_mutex_t cwcycle_lock29;  
pthread_mutex_t cwcycle_lock30;  
pthread_mutex_t cwcycle_lock31;  

static int16_t cw_cc_list_size1=0;
static int16_t cw_cc_list_size2=0;
static int16_t cw_cc_list_size3=0;
static int16_t cw_cc_list_size4=0;
static int16_t cw_cc_list_size5=0;
static int16_t cw_cc_list_size6=0;
static int16_t cw_cc_list_size7=0;
static int16_t cw_cc_list_size8=0;
static int16_t cw_cc_list_size9=0;
static int16_t cw_cc_list_size10=0;
static int16_t cw_cc_list_size11=0;
static int16_t cw_cc_list_size12=0;
static int16_t cw_cc_list_size13=0;
static int16_t cw_cc_list_size14=0;
static int16_t cw_cc_list_size15=0;
static int16_t cw_cc_list_size16=0;
static int16_t cw_cc_list_size17=0;
static int16_t cw_cc_list_size18=0;
static int16_t cw_cc_list_size19=0;
static int16_t cw_cc_list_size20=0;
static int16_t cw_cc_list_size21=0;
static int16_t cw_cc_list_size22=0;
static int16_t cw_cc_list_size23=0;
static int16_t cw_cc_list_size24=0;
static int16_t cw_cc_list_size25=0;
static int16_t cw_cc_list_size26=0;
static int16_t cw_cc_list_size27=0;
static int16_t cw_cc_list_size28=0;
static int16_t cw_cc_list_size29=0;
static int16_t cw_cc_list_size30=0;
static int16_t cw_cc_list_size31=0;

static time_t last_cwcyclecleaning;
static 	LLIST *res_nodes;
//static 	LLIST *res_nodes_root;
static int32_t item_to_delete;

struct element
{
	struct s_cw_cycle_check *key;
    struct element *left;
    struct element *right;
    int16_t height;
} *tRoot = NULL, *tRoot2 = NULL, *tRoot3 = NULL, *tRoot4 = NULL, *tRoot5 = NULL, *tRoot6 = NULL, *tRoot7 = NULL, *tRoot8 = NULL,
  *tRoot9 = NULL,  *tRoot10 = NULL, *tRoot11 = NULL,  *tRoot12 = NULL, *tRoot13 = NULL, *tRoot14 = NULL,  *tRoot15 = NULL, *tRoot16 = NULL,
   *tRoot17 = NULL , *tRoot18 = NULL, *tRoot19 = NULL, *tRoot20 = NULL, *tRoot21 = NULL, *tRoot22 = NULL, *tRoot23 = NULL, *tRoot24 = NULL,
   *tRoot25 = NULL, *tRoot26 = NULL, *tRoot27 = NULL, *tRoot28 = NULL, *tRoot29 = NULL, *tRoot30 = NULL, *tRoot31 = NULL;   

static time_t nowcwc;
static int32_t kct;
static struct s_cw_cycle_check *key_tmp;
//struct element *element_list;

int8_t get_ecmofs(uint16_t caid)
{

	int8_t ofs = -1;
	if (caid == 0x098C) {ofs = 9;}
	else
	if (caid == 0x09CD) {ofs =  10;} 
	else
	if (caid == 0x0963) {ofs =  11;}
	else
	if (caid == 0x1810) {ofs =  12;}
	else
	if (caid == 0x0D96) {ofs =  13;}
	else
	if (caid == 0x0D97) {ofs =  14;}
	else
	if (caid == 0x0D95) {ofs =  15;}
	else 
	if (caid == 0x0624) {ofs =  16;}
	else
	if (caid == 0x1803) {ofs =  17;}
	else
	if (caid == 0x1801 || caid == 0x1833 || caid == 0x1834 || caid == 0x1835 || caid == 0x1702 || caid == 0x1722 ) {ofs =  18;}
	else
	if (caid == 0x1802) {ofs =  19;}
	else
	if (caid == 0x1843) {ofs =  20;}
	else
	if (caid == 0x0B02) {ofs =  21;}
	else
	if (caid == 0x1805) {ofs =  22;}
	 
	if (ofs != -1) return ofs;

	switch(caid >> 8)
	{
	case 0x01: //SECA
	ofs =1;
		break;
	case 0x05: //VIACCESS
	ofs = 2;
		break;
	case 0x06: //IRDETO
	ofs = 3;
		break;
	case 0x09: //VIDEOGUARD
	ofs = 4;
		break;
	case 0x0B: //CONAX
	ofs = 5;
		break;
	case 0x0D: //CRYPTOWORKS
	ofs = 6;
		break;
	case 0x17: //BETACRYPT
	ofs = 8;
		break;
	case 0x18: //NAGRA
	ofs = 8;
		break;
	default:
	ofs = 1;
		break;
	}
	return ofs;
}

int8_t get_ecmofs_cwc(ECM_REQUEST *er)
{
	uint16_t caid = er->caid;

	if (caid == 0x0100 && er->prid == 0x00006A) { return 23; }
	else
	if (caid == 0x0100 && er->prid == 0x00006C) { return 24; }
	else
	if (caid == 0x0100 && er->prid == 0x00006D) { return 25; }
	else
	if (caid == 0x0500 && er->prid == 0x043800) { return 26; }
	else
	if (caid == 0x0500 && er->prid == 0x042800) { return 27; }
	else
	if (caid == 0x0500 && er->prid == 0x032830) { return 28; }
	else
	if (caid == 0x0500 && er->prid == 0x041950) { return 29; }
	else
	if (caid == 0x0500 && er->prid == 0x032920) { return 30; }
	else
	if (caid == 0x0100 && er->prid == 0x000068) { return 31; }



	int8_t ofs = -1;
	if (caid == 0x098C) {ofs = 9;}
	else
	if (caid == 0x09CD) {ofs =  10;} 
	else
	if (caid == 0x0963) {ofs =  11;}
	else
	if (caid == 0x1810) {ofs =  12;}
	else
	if (caid == 0x0D96) {ofs =  13;}
	else
	if (caid == 0x0D97) {ofs =  14;}
	else
	if (caid == 0x0D95) {ofs =  15;}
	else 
	if (caid == 0x0624) {ofs =  16;}
	else
	if (caid == 0x1803) {ofs =  17;}
	else
	if (caid == 0x1801 || caid == 0x1833 || caid == 0x1834 || caid == 0x1835 || caid == 0x1702 || caid == 0x1722 ) {ofs =  18;}
	else
	if (caid == 0x1802) {ofs =  19;}
	else
	if (caid == 0x1843) {ofs =  20;}
	else
	if (caid == 0x0B02) {ofs =  21;}
	else
	if (caid == 0x1805) {ofs =  22;}
	 
	if (ofs != -1) return ofs;

	switch(caid >> 8)
	{
	case 0x01: //SECA
	ofs =1;
		break;
	case 0x05: //VIACCESS
	ofs = 2;
		break;
	case 0x06: //IRDETO
	ofs = 3;
		break;
	case 0x09: //VIDEOGUARD
	ofs = 4;
		break;
	case 0x0B: //CONAX
	ofs = 5;
		break;
	case 0x0D: //CRYPTOWORKS
	ofs = 6;
		break;
	case 0x17: //BETACRYPT
	ofs = 8;
		break;
	case 0x18: //NAGRA
	ofs = 8;
		break;
	default:
	ofs = 1;
		break;
	}
	return ofs;
}


static void lock_cwc(int8_t test)
{
	switch(test)
  	{
	case 1: while(pthread_mutex_lock(&cwcycle_lock1) !=0) { cs_sleepus(20); }
	break;
	case 2: while(pthread_mutex_lock(&cwcycle_lock2) !=0) { cs_sleepus(20); }
	break;
	case 3: while(pthread_mutex_lock(&cwcycle_lock3) !=0) { cs_sleepus(20); }
	break;
	case 4: while(pthread_mutex_lock(&cwcycle_lock4) !=0) { cs_sleepus(20); }
	break;
	case 5: while(pthread_mutex_lock(&cwcycle_lock5) !=0) { cs_sleepus(20); }
	break;
	case 6: while(pthread_mutex_lock(&cwcycle_lock6) !=0) { cs_sleepus(20); }
	break;
	case 7: while(pthread_mutex_lock(&cwcycle_lock7) !=0) { cs_sleepus(20); }
	break;
	case 8: while(pthread_mutex_lock(&cwcycle_lock8) !=0) { cs_sleepus(20); }
	break;
	case 9: while(pthread_mutex_lock(&cwcycle_lock9) !=0) { cs_sleepus(20); }
	break;
	case 10: while(pthread_mutex_lock(&cwcycle_lock10) !=0) { cs_sleepus(20); }
	break;
	case 11: while(pthread_mutex_lock(&cwcycle_lock11) !=0) { cs_sleepus(20); }
	break;
	case 12: while(pthread_mutex_lock(&cwcycle_lock12) !=0) { cs_sleepus(20); }
	break;
	case 13: while(pthread_mutex_lock(&cwcycle_lock13) !=0) { cs_sleepus(20); }
	break;
	case 14: while(pthread_mutex_lock(&cwcycle_lock14) !=0) { cs_sleepus(20); }
	break;
	case 15: while(pthread_mutex_lock(&cwcycle_lock15) !=0) { cs_sleepus(20); }
	break;
	case 16: while(pthread_mutex_lock(&cwcycle_lock16) !=0) { cs_sleepus(20); }
	break;
	case 17: while(pthread_mutex_lock(&cwcycle_lock17) !=0) { cs_sleepus(20); }
	break;
	case 18: while(pthread_mutex_lock(&cwcycle_lock18) !=0) { cs_sleepus(20); }
	break;
	case 19: while(pthread_mutex_lock(&cwcycle_lock19) !=0) { cs_sleepus(20); }
	break;
	case 20: while(pthread_mutex_lock(&cwcycle_lock20) !=0) { cs_sleepus(20); }
	break;
	case 21: while(pthread_mutex_lock(&cwcycle_lock21) !=0) { cs_sleepus(20); }
	break;
	case 22: while(pthread_mutex_lock(&cwcycle_lock22) !=0) { cs_sleepus(20); }
	break;
	case 23: while(pthread_mutex_lock(&cwcycle_lock23) !=0) { cs_sleepus(20); }
	break;
	case 24: while(pthread_mutex_lock(&cwcycle_lock24) !=0) { cs_sleepus(20); }
	break;
	case 25: while(pthread_mutex_lock(&cwcycle_lock25) !=0) { cs_sleepus(20); }
	break;
	case 26: while(pthread_mutex_lock(&cwcycle_lock26) !=0) { cs_sleepus(20); }
	break;
	case 27: while(pthread_mutex_lock(&cwcycle_lock27) !=0) { cs_sleepus(20); }
	break;
	case 28: while(pthread_mutex_lock(&cwcycle_lock28) !=0) { cs_sleepus(20); }
	break;
	case 29: while(pthread_mutex_lock(&cwcycle_lock29) !=0) { cs_sleepus(20); }
	break;
	case 30: while(pthread_mutex_lock(&cwcycle_lock30) !=0) { cs_sleepus(20); }
	break;
	case 31: while(pthread_mutex_lock(&cwcycle_lock31) !=0) { cs_sleepus(20); }
	break;
	}
}

static void unlock_cwc(int8_t test)
{
 	switch(test)
  	{
	case 1: pthread_mutex_unlock(&cwcycle_lock1); 
	 break;
	case 2: pthread_mutex_unlock(&cwcycle_lock2); 
	 break;                                  
	case 3: pthread_mutex_unlock(&cwcycle_lock3); 
	 break;
	case 4: pthread_mutex_unlock(&cwcycle_lock4); 
	break;
	case 5: pthread_mutex_unlock(&cwcycle_lock5); 
	 break;
	case 6: pthread_mutex_unlock(&cwcycle_lock6); 
	 break;
	case 7: pthread_mutex_unlock(&cwcycle_lock7); 
	 break;
	case 8: pthread_mutex_unlock(&cwcycle_lock8); 
	 break;
	case 9: pthread_mutex_unlock(&cwcycle_lock9);
	break;
	case 10: pthread_mutex_unlock(&cwcycle_lock10);
	break;
	case 11: pthread_mutex_unlock(&cwcycle_lock11);
	break;
	case 12: pthread_mutex_unlock(&cwcycle_lock12);
	break;
	case 13: pthread_mutex_unlock(&cwcycle_lock13);
	break;
	case 14: pthread_mutex_unlock(&cwcycle_lock14);
	break;
	case 15: pthread_mutex_unlock(&cwcycle_lock15);
	break;
	case 16: pthread_mutex_unlock(&cwcycle_lock16);
	break;
	case 17: pthread_mutex_unlock(&cwcycle_lock17);
	break;
	case 18: pthread_mutex_unlock(&cwcycle_lock18);
	break;
	case 19: pthread_mutex_unlock(&cwcycle_lock19);
	break;
	case 20: pthread_mutex_unlock(&cwcycle_lock20);
	break;
	case 21: pthread_mutex_unlock(&cwcycle_lock21);
	break;
	case 22: pthread_mutex_unlock(&cwcycle_lock22);
	break;	 
	case 23: pthread_mutex_unlock(&cwcycle_lock23);
	break;	 
	case 24: pthread_mutex_unlock(&cwcycle_lock24);
	break;	 
	case 25: pthread_mutex_unlock(&cwcycle_lock25);
	break;	 
	case 26: pthread_mutex_unlock(&cwcycle_lock26);
	break;	 
	case 27: pthread_mutex_unlock(&cwcycle_lock27);
	break;	 
	case 28: pthread_mutex_unlock(&cwcycle_lock28);
	break;	 
	case 29: pthread_mutex_unlock(&cwcycle_lock29);
	break;	 
	case 30: pthread_mutex_unlock(&cwcycle_lock30);
	break;	 
	case 31: pthread_mutex_unlock(&cwcycle_lock31);
	break;	 
	}
}

static void cwc_init(void)
{
 res_nodes=ll_create("delete_res_nodes");
// res_nodes_root=ll_create("delete_res_nodes_root");
}

void cwc_init_clean(void)
{
last_cwcyclecleaning = time(NULL);
cwc_init(); 
}

static void inOrder2(struct element *root){
if (root != NULL) 
{
inOrder2(root->left);
add_garbage(root->key);
add_garbage(root);
inOrder2(root->right);
}
}

void cwc_destroy(void)
{
ll_destroy(&res_nodes); 
//ll_destroy(res_nodes_root);
inOrder2(tRoot);
inOrder2(tRoot2);
inOrder2(tRoot3);
inOrder2(tRoot4);
inOrder2(tRoot5);
inOrder2(tRoot6);
inOrder2(tRoot7);
inOrder2(tRoot8);
inOrder2(tRoot9);
inOrder2(tRoot10);
inOrder2(tRoot11);
inOrder2(tRoot12);
inOrder2(tRoot13);
inOrder2(tRoot14);
inOrder2(tRoot15);
inOrder2(tRoot16);
inOrder2(tRoot17);
inOrder2(tRoot18);
inOrder2(tRoot19);
inOrder2(tRoot20);
inOrder2(tRoot21);
inOrder2(tRoot22);
inOrder2(tRoot23);
inOrder2(tRoot24);
inOrder2(tRoot25);
inOrder2(tRoot26);
inOrder2(tRoot27);
inOrder2(tRoot28);
inOrder2(tRoot29);
inOrder2(tRoot30);
inOrder2(tRoot31);
pthread_mutex_destroy(&cwcycle_lock1);
pthread_mutex_destroy(&cwcycle_lock2);
pthread_mutex_destroy(&cwcycle_lock3);
pthread_mutex_destroy(&cwcycle_lock4);
pthread_mutex_destroy(&cwcycle_lock5);
pthread_mutex_destroy(&cwcycle_lock6);
pthread_mutex_destroy(&cwcycle_lock7);
pthread_mutex_destroy(&cwcycle_lock8);
pthread_mutex_destroy(&cwcycle_lock9);
pthread_mutex_destroy(&cwcycle_lock10);
pthread_mutex_destroy(&cwcycle_lock11);
pthread_mutex_destroy(&cwcycle_lock12);
pthread_mutex_destroy(&cwcycle_lock13);
pthread_mutex_destroy(&cwcycle_lock14);
pthread_mutex_destroy(&cwcycle_lock15);
pthread_mutex_destroy(&cwcycle_lock16);
pthread_mutex_destroy(&cwcycle_lock17);
pthread_mutex_destroy(&cwcycle_lock18);
pthread_mutex_destroy(&cwcycle_lock19);
pthread_mutex_destroy(&cwcycle_lock20);
pthread_mutex_destroy(&cwcycle_lock21);
pthread_mutex_destroy(&cwcycle_lock22);
pthread_mutex_destroy(&cwcycle_lock23);
pthread_mutex_destroy(&cwcycle_lock24);
pthread_mutex_destroy(&cwcycle_lock25);
pthread_mutex_destroy(&cwcycle_lock26);
pthread_mutex_destroy(&cwcycle_lock27);
pthread_mutex_destroy(&cwcycle_lock28);
pthread_mutex_destroy(&cwcycle_lock29);
pthread_mutex_destroy(&cwcycle_lock30);
pthread_mutex_destroy(&cwcycle_lock31);
}

int32_t cache_size_cwc(void)
{
return 
cw_cc_list_size1+
cw_cc_list_size2+
cw_cc_list_size3+
cw_cc_list_size4+
cw_cc_list_size5+
cw_cc_list_size6+
cw_cc_list_size7+
cw_cc_list_size8+
cw_cc_list_size9+
cw_cc_list_size10+
cw_cc_list_size11+
cw_cc_list_size12+
cw_cc_list_size13+
cw_cc_list_size14+
cw_cc_list_size15+
cw_cc_list_size16+
cw_cc_list_size17+
cw_cc_list_size18+
cw_cc_list_size19+
cw_cc_list_size20+
cw_cc_list_size21+
cw_cc_list_size22+
cw_cc_list_size23+
cw_cc_list_size24+
cw_cc_list_size25+
cw_cc_list_size26+
cw_cc_list_size27+
cw_cc_list_size28+
cw_cc_list_size29+
cw_cc_list_size30+
cw_cc_list_size31;
}

int16_t cache_size_cwc_selected(int8_t test)
{
 int16_t cw_cc_list_sizex;
 
	   switch(test)
  	   {
		case 1: cw_cc_list_sizex=cw_cc_list_size1; 
		break;
		case 2: cw_cc_list_sizex=cw_cc_list_size2;
		break;
		case 3: cw_cc_list_sizex=cw_cc_list_size3;
		break;
		case 4: cw_cc_list_sizex=cw_cc_list_size4;
		break;
		case 5: cw_cc_list_sizex=cw_cc_list_size5;
		break;
		case 6: cw_cc_list_sizex=cw_cc_list_size6;
	 	break;
		case 7: cw_cc_list_sizex=cw_cc_list_size7;
	 	break;
	 	case 8: cw_cc_list_sizex=cw_cc_list_size8;
	 	break;
	 	case 9: cw_cc_list_sizex=cw_cc_list_size9;
	 	break;
		case 10: cw_cc_list_sizex=cw_cc_list_size10;
	 	break;
		case 11: cw_cc_list_sizex=cw_cc_list_size11;
	 	break;
		case 12: cw_cc_list_sizex=cw_cc_list_size12;
	 	break;
		case 13: cw_cc_list_sizex=cw_cc_list_size13;
	 	break;
		case 14: cw_cc_list_sizex=cw_cc_list_size14;
	 	break;
		case 15: cw_cc_list_sizex=cw_cc_list_size15;
	 	break;
		case 16: cw_cc_list_sizex=cw_cc_list_size16;
	 	break;
		case 17: cw_cc_list_sizex=cw_cc_list_size17;
	 	break;
		case 18: cw_cc_list_sizex=cw_cc_list_size18;
	 	break;
		case 19: cw_cc_list_sizex=cw_cc_list_size19;
	 	break;
		case 20: cw_cc_list_sizex=cw_cc_list_size20;
	 	break;
		case 21: cw_cc_list_sizex=cw_cc_list_size21;
	 	break;
		case 22: cw_cc_list_sizex=cw_cc_list_size22;
	 	break;
		case 23: cw_cc_list_sizex=cw_cc_list_size23;
	 	break;
		case 24: cw_cc_list_sizex=cw_cc_list_size24;
	 	break;
		case 25: cw_cc_list_sizex=cw_cc_list_size25;
	 	break;
		case 26: cw_cc_list_sizex=cw_cc_list_size26;
	 	break;
		case 27: cw_cc_list_sizex=cw_cc_list_size27;
	 	break;
		case 28: cw_cc_list_sizex=cw_cc_list_size28;
	 	break;
		case 29: cw_cc_list_sizex=cw_cc_list_size29;
	 	break;
		case 30: cw_cc_list_sizex=cw_cc_list_size30;
	 	break;
		case 31: cw_cc_list_sizex=cw_cc_list_size31;
	 	break;
	   }
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
 return cw_cc_list_sizex;
#pragma GCC diagnostic pop 
}

void cwc_init_lock(void)
{
cwc_init_clean();

while(pthread_mutex_init(&cwcycle_lock1, NULL) !=0)  { cs_sleepus(20); }
while(pthread_mutex_init(&cwcycle_lock2, NULL) !=0)  { cs_sleepus(20); }
while(pthread_mutex_init(&cwcycle_lock3, NULL) !=0)  { cs_sleepus(20); }
while(pthread_mutex_init(&cwcycle_lock4, NULL) !=0)  { cs_sleepus(20); }
while(pthread_mutex_init(&cwcycle_lock5, NULL) !=0)  { cs_sleepus(20); }
while(pthread_mutex_init(&cwcycle_lock6, NULL) !=0)  { cs_sleepus(20); }
while(pthread_mutex_init(&cwcycle_lock7, NULL) !=0)  { cs_sleepus(20); }
while(pthread_mutex_init(&cwcycle_lock8, NULL) !=0)  { cs_sleepus(20); }
while(pthread_mutex_init(&cwcycle_lock9, NULL) !=0)  { cs_sleepus(20); }
while(pthread_mutex_init(&cwcycle_lock10, NULL) !=0)  { cs_sleepus(20); }
while(pthread_mutex_init(&cwcycle_lock11, NULL) !=0)  { cs_sleepus(20); }
while(pthread_mutex_init(&cwcycle_lock12, NULL) !=0)  { cs_sleepus(20); }
while(pthread_mutex_init(&cwcycle_lock13, NULL) !=0)  { cs_sleepus(20); }
while(pthread_mutex_init(&cwcycle_lock14, NULL) !=0)  { cs_sleepus(20); }
while(pthread_mutex_init(&cwcycle_lock15, NULL) !=0)  { cs_sleepus(20); }
while(pthread_mutex_init(&cwcycle_lock16, NULL) !=0)  { cs_sleepus(20); }
while(pthread_mutex_init(&cwcycle_lock17, NULL) !=0)  { cs_sleepus(20); }
while(pthread_mutex_init(&cwcycle_lock18, NULL) !=0)  { cs_sleepus(20); }
while(pthread_mutex_init(&cwcycle_lock19, NULL) !=0)  { cs_sleepus(20); }
while(pthread_mutex_init(&cwcycle_lock20, NULL) !=0)  { cs_sleepus(20); }
while(pthread_mutex_init(&cwcycle_lock21, NULL) !=0)  { cs_sleepus(20); }
while(pthread_mutex_init(&cwcycle_lock22, NULL) !=0)  { cs_sleepus(20); }
while(pthread_mutex_init(&cwcycle_lock23, NULL) !=0)  { cs_sleepus(20); }
while(pthread_mutex_init(&cwcycle_lock24, NULL) !=0)  { cs_sleepus(20); }
while(pthread_mutex_init(&cwcycle_lock25, NULL) !=0)  { cs_sleepus(20); }
while(pthread_mutex_init(&cwcycle_lock26, NULL) !=0)  { cs_sleepus(20); }
while(pthread_mutex_init(&cwcycle_lock27, NULL) !=0)  { cs_sleepus(20); }
while(pthread_mutex_init(&cwcycle_lock28, NULL) !=0)  { cs_sleepus(20); }
while(pthread_mutex_init(&cwcycle_lock29, NULL) !=0)  { cs_sleepus(20); }
while(pthread_mutex_init(&cwcycle_lock30, NULL) !=0)  { cs_sleepus(20); }
while(pthread_mutex_init(&cwcycle_lock31, NULL) !=0)  { cs_sleepus(20); }
}


//----------------------------------------------

static int16_t comparecwc(struct s_cw_cycle_check *a,struct s_cw_cycle_check *b)
{
if(a->caid < b->caid ) { return -1;}
else
if(a->caid > b->caid ) { return  1;}
else
if(a->provid < b->provid) { return -1;}
else
if(a->provid > b->provid) { return 1;}
else
if(a->sid < b->sid) { return -1;}
else
if(a->sid > b->sid) { return 1;}
else
if(a->chid < b->chid) { return -1;}
else
if(a->chid > b->chid) { return 1;}
/*else
if(a->ecmlen < b->ecmlen) { return -1;}
else
if(a->ecmlen > b->ecmlen) { return 1;}
else*/
return 0;
}

static struct element* searchelement(struct element *root,struct s_cw_cycle_check *key){
if (root == NULL) return NULL;
else {
if (comparecwc(root->key,key)==0) return root;
else {
if (comparecwc(key,root->key) == -1) return searchelement(root->left,key);
else return searchelement(root->right,key);
}
}
}

/*
    get the height of a node
*/
static int16_t height( struct element *n )
{
    if( n == NULL )
        return -1;
    else
        return n->height;
}
 
/*
    get maximum value of two integers
*/
static int16_t max( int16_t l, int16_t r)
{
    return l > r ? l: r;
}
  
static struct element *single_rotate_with_left( struct element *k2 )
{
    struct element *k1;/* = NULL;*/
 
    k1 = k2->left;
    k2->left = k1->right;
    k1->right = k2;
 
    k2->height = max( height( k2->left ), height( k2->right ) ) + 1;
    k1->height = max( height( k1->left ), k2->height ) + 1;
    return k1; /* new root */
}
 
/*
    perform a rotation between a node (k1) and its right child
 
    note: call single_rotate_with_right only if
    the k1 node has a right child
*/
 
static struct element *single_rotate_with_right( struct element* k1 )
{
    struct element *k2;
 
    k2 = k1->right;
    k1->right = k2->left;
    k2->left = k1;
 
    k1->height = max( height( k1->left ), height( k1->right ) ) + 1;
    k2->height = max( height( k2->right ), k1->height ) + 1;
 
    return k2;  /* New root */
}
 
/*
 
    perform the left-right double rotation,
 
    note: call double_rotate_with_left only if k3 node has
    a left child and k3's left child has a right child
*/
 
static struct element* double_rotate_with_left( struct element *k3 )
{
    /* Rotate between k1 and k2 */
    k3->left = single_rotate_with_right( k3->left );
 
    /* Rotate between K3 and k2 */
    return single_rotate_with_left( k3 );
}
 
/*
    perform the right-left double rotation
 
   notes: call double_rotate_with_right only if k1 has a
   right child and k1's right child has a left child
*/
 
 
 
static struct element *double_rotate_with_right( struct element *k1 )
{
    /* rotate between K3 and k2 */
    k1->right = single_rotate_with_left( k1->right );
 
    /* rotate between k1 and k2 */
    return single_rotate_with_right( k1 );
}
 
/*
    insert a new node into the tree
*/

static struct element *Newelement(struct s_cw_cycle_check *key)
{
    struct element *element;
    if (!cs_malloc_nonull(&element,sizeof(struct element))) {;}                   
    element->key   = key;
  	element->right = element->left   = NULL; 
    element->height = 0;  // new element is initially added at leaf
    return(element);
}
 
struct element *insertcwc(struct element  *element,struct s_cw_cycle_check *key)
{
    if (key == NULL) { return element; }
	if( element == NULL )
    {
        /* Create and return a one-node tree */
        element = Newelement(key);
        if( element == NULL )
        {
            fprintf (stderr, "Out of memory!!! (insert)\n");
            exit(1);
        }
        return element;
	}
    else
	if(comparecwc(key,element->key)==-1 )
    {
        element->left = insertcwc(element->left,key);
        if((height( element->left ) - height( element->right )) == 2 )
        {
		 if( comparecwc(key,element->left->key)==-1)
                element = single_rotate_with_left( element );
         else
                element = double_rotate_with_left( element );
        }       
    }
    else 
	if( comparecwc(key,element->key)==1 )
    {
        element->right = insertcwc( element->right,key );
        if((height( element->right ) - height( element->left )) == 2 )
        { 
		    if( comparecwc(key,element->right->key)==+1 )
                element = single_rotate_with_right( element );
            else
               element = double_rotate_with_right( element );
        }       
    }
    /* Else X is in the tree already; we'll do nothing */
 
    element->height = max( height( element->left ), height( element->right ) ) + 1;
    return element;
}
 
// A utility function to print preorder traversal of the tree.
// The function also prints height of every element
/*static void preOrder(struct element *root)
{
    if(root != NULL)
    {
		cw_cc_list_size++;
        preOrder(root->left);
        preOrder(root->right);
    }
}
*/
static void inOrder(struct element *root){
if (root != NULL)
{
inOrder(root->left);
key_tmp = root->key;
if(key_tmp->time < deltime)    // delete Entry which old to hold list small
 { item_to_delete++; }
inOrder(root->right);
}
}

static void inOrder1(struct element *root){
if (root != NULL) 
{
inOrder1(root->left);
ll_append_nolock(res_nodes,root->key);
//ll_append_nolock(res_nodes_root,root);
add_garbage(root);
inOrder1(root->right);
}
}

////////////////////////////////////////////////////////////

static void clean_part(int8_t i)
{
//  	if(cache_size_cwc_selected(i) <  cfg.maxcyclelist) return;
	item_to_delete=0;
	deltime = nowcwc - kct; 

	
	switch(i)
  	{
	case 1: inOrder(tRoot);
	 break;
	case 2: inOrder(tRoot2);
	break;
	case 3: inOrder(tRoot3);
	 break;
	case 4: inOrder(tRoot4);
	break;
	case 5: inOrder(tRoot5);
	 break;
	case 6: inOrder(tRoot6);
	 break;
	case 7: inOrder(tRoot7);
	 break;
	case 8: inOrder(tRoot8);
	 break;
	case 9: inOrder(tRoot9);
	 break;
	case 10: inOrder(tRoot10);
	 break;
	case 11: inOrder(tRoot11);
	 break;
	case 12: inOrder(tRoot12);
	 break;
	case 13: inOrder(tRoot13);
	 break;
	case 14: inOrder(tRoot14);
	 break;
	case 15: inOrder(tRoot15);
	 break;
	case 16: inOrder(tRoot16);
	 break;
	case 17: inOrder(tRoot17);
	 break;
	case 18: inOrder(tRoot18);
	 break;
	case 19: inOrder(tRoot19);
	 break;
	case 20: inOrder(tRoot20);
	 break;
	case 21: inOrder(tRoot21);
	 break;
	case 22: inOrder(tRoot22);
	 break;
	case 23: inOrder(tRoot23);
	 break;
	case 24: inOrder(tRoot24);
	 break;
	case 25: inOrder(tRoot25);
	 break;
	case 26: inOrder(tRoot26);
	 break;
	case 27: inOrder(tRoot27);
	 break;
	case 28: inOrder(tRoot28);
	 break;
	case 29: inOrder(tRoot29);
	 break;
	case 30: inOrder(tRoot30);
	 break;
	case 31: inOrder(tRoot31);
	 break;
	}	

 if (item_to_delete>50 /*&& cw_cc_list_size>=cfg.maxcyclelist*/)
 {
	switch(i)
  	{
	case 1: inOrder1(tRoot); tRoot=NULL;  
	 break;
	case 2: inOrder1(tRoot2); tRoot2=NULL; 
	break;
	case 3: inOrder1(tRoot3); tRoot3=NULL; 
	 break;
	case 4: inOrder1(tRoot4); tRoot4=NULL; 
	break;
	case 5: inOrder1(tRoot5); tRoot5=NULL; 
	 break;
	case 6: inOrder1(tRoot6); tRoot6=NULL;
	 break;
	case 7: inOrder1(tRoot7); tRoot7=NULL;
	 break;
	case 8: inOrder1(tRoot8); tRoot8=NULL;
	 break;
	case 9: inOrder1(tRoot9); tRoot9=NULL;
	 break;
	case 10: inOrder1(tRoot10); tRoot10=NULL;
	 break;
	case 11: inOrder1(tRoot11); tRoot11=NULL;
	 break;
	case 12: inOrder1(tRoot12); tRoot12=NULL;
	 break;
	case 13: inOrder1(tRoot13); tRoot13=NULL;
	 break;
	case 14: inOrder1(tRoot14); tRoot14=NULL;
	 break;
	case 15: inOrder1(tRoot15); tRoot15=NULL;
	 break;
	case 16: inOrder1(tRoot16); tRoot16=NULL;
	 break;
	case 17: inOrder1(tRoot17); tRoot17=NULL;
	 break;
	case 18: inOrder1(tRoot18); tRoot18=NULL;
	 break;
	case 19: inOrder1(tRoot19); tRoot19=NULL;
	 break;
	case 20: inOrder1(tRoot20); tRoot20=NULL;
	 break;
	case 21: inOrder1(tRoot21); tRoot21=NULL;
	 break;
	case 22: inOrder1(tRoot22); tRoot22=NULL;
	 break;
	case 23: inOrder1(tRoot23); tRoot23=NULL;
	 break;
	case 24: inOrder1(tRoot24); tRoot24=NULL;
	 break;
	case 25: inOrder1(tRoot25); tRoot25=NULL;
	 break;
	case 26: inOrder1(tRoot26); tRoot26=NULL;
	 break;
	case 27: inOrder1(tRoot27); tRoot27=NULL;
	 break;
	case 28: inOrder1(tRoot28); tRoot28=NULL;
	 break;
	case 29: inOrder1(tRoot29); tRoot29=NULL;
	 break;
	case 30: inOrder1(tRoot30); tRoot30=NULL;
	 break;
	case 31: inOrder1(tRoot31); tRoot31=NULL;
	 break;
	}	
	
	struct s_cw_cycle_check *cwc;
	LL_ITER it = ll_iter_create(res_nodes);

	while((cwc = ll_iter_next_nolock(&it)))
	{
	 if(!(cwc->time < deltime))    		   // delete Entry which old to hold list small
	 {
	   switch(i)
  	   {
		case 1: tRoot = insertcwc(tRoot,cwc); 
		break;
		case 2: tRoot2 = insertcwc(tRoot2,cwc);
		break;
		case 3: tRoot3 = insertcwc(tRoot3,cwc);
		break;
		case 4: tRoot4 = insertcwc(tRoot4,cwc);
		break;
		case 5: tRoot5 = insertcwc(tRoot5,cwc);
		break;
		case 6: tRoot6 = insertcwc(tRoot6,cwc);
	 	break;
		case 7: tRoot7 = insertcwc(tRoot7,cwc);
	 	break;
	 	case 8: tRoot8 = insertcwc(tRoot8,cwc);
	 	break;
	 	case 9: tRoot9 = insertcwc(tRoot9,cwc);
	 	break;
		case 10: tRoot10 = insertcwc(tRoot10,cwc);
	 	break;
		case 11: tRoot11 = insertcwc(tRoot11,cwc);
	 	break;
		case 12: tRoot12 = insertcwc(tRoot12,cwc);
	 	break;
		case 13: tRoot13= insertcwc(tRoot13,cwc);
	 	break;
		case 14: tRoot14 = insertcwc(tRoot14,cwc);
	 	break;
		case 15: tRoot15 = insertcwc(tRoot15,cwc);
	 	break;
		case 16: tRoot16 = insertcwc(tRoot16,cwc);
	 	break;
		case 17: tRoot17 = insertcwc(tRoot17,cwc);
	 	break;
		case 18: tRoot18 = insertcwc(tRoot18,cwc);
	 	break;
		case 19: tRoot19 = insertcwc(tRoot19,cwc);
	 	break;
		case 20: tRoot20 = insertcwc(tRoot20,cwc);
	 	break;
		case 21: tRoot21 = insertcwc(tRoot21,cwc);
	 	break;
		case 22: tRoot22 = insertcwc(tRoot22,cwc);
	 	break;
		case 23: tRoot23 = insertcwc(tRoot23,cwc);
	 	break;
		case 24: tRoot24 = insertcwc(tRoot24,cwc);
	 	break;
		case 25: tRoot25 = insertcwc(tRoot25,cwc);
	 	break;
		case 26: tRoot26 = insertcwc(tRoot26,cwc);
	 	break;
		case 27: tRoot27 = insertcwc(tRoot27,cwc);
	 	break;
		case 28: tRoot28 = insertcwc(tRoot28,cwc);
	 	break;
		case 29: tRoot29 = insertcwc(tRoot29,cwc);
	 	break;
		case 30: tRoot30 = insertcwc(tRoot30,cwc);
	 	break;
		case 31: tRoot31 = insertcwc(tRoot31,cwc);
	 	break;
	   }	
	}
	else
	{ 
	   free(cwc);
	   switch(i)
  	   {
		case 1: cw_cc_list_size1--; 
		break;
		case 2: cw_cc_list_size2--;
		break;
		case 3: cw_cc_list_size3--;
		break;
		case 4: cw_cc_list_size4--;
		break;
		case 5: cw_cc_list_size5--;
		break;
		case 6: cw_cc_list_size6--;
	 	break;
		case 7: cw_cc_list_size7--;
	 	break;
	 	case 8: cw_cc_list_size8--;
	 	break;
	 	case 9: cw_cc_list_size9--;
	 	break;
		case 10: cw_cc_list_size10--;
	 	break;
		case 11: cw_cc_list_size11--;
	 	break;
		case 12: cw_cc_list_size12--;
	 	break;
		case 13: cw_cc_list_size13--;
	 	break;
		case 14: cw_cc_list_size14--;
	 	break;
		case 15: cw_cc_list_size15--;
	 	break;
		case 16: cw_cc_list_size16--;
	 	break;
		case 17: cw_cc_list_size17--;
	 	break;
		case 18: cw_cc_list_size18--;
	 	break;
		case 19: cw_cc_list_size19--;
	 	break;
		case 20: cw_cc_list_size20--;
	 	break;
		case 21: cw_cc_list_size21--;
	 	break;
		case 22: cw_cc_list_size22--;
	 	break;
		case 23: cw_cc_list_size23--;
	 	break;
		case 24: cw_cc_list_size24--;
	 	break;
		case 25: cw_cc_list_size25--;
	 	break;
		case 26: cw_cc_list_size26--;
	 	break;
		case 27: cw_cc_list_size27--;
	 	break;
		case 28: cw_cc_list_size28--;
	 	break;
		case 29: cw_cc_list_size29--;
	 	break;
		case 30: cw_cc_list_size30--;
	 	break;
		case 31: cw_cc_list_size31--;
	 	break;
	   }	
	}
	ll_iter_remove_nolock(&it);
   }
 }	
}	
 	
void cleanupcwcycle(void)
{	
// int16_t cw_cc_list_sizex;
 
//		if(!cfg.cwcycle_delete) temp..   removed
//		{
//		 return;
//		}
		time_t now1 = time(NULL);
 
 		if(last_cwcyclecleaning + 1500 > now1)  //only clean once every 15min
			{ return; }
		last_cwcyclecleaning=now1;

 		kct = cfg.keepcycletime * 60 + 30; // if keepcycletime is set, wait more before deleting
		nowcwc=time(NULL);

	int8_t i;

	for (i=1;i<=31;i++)
	{
	 if(i == 9 || i == 10 || i == 11 || i == 4) { continue; }
	 //cw_cc_list_sizex = cache_size_cwc_selected(i);
	 //if(cw_cc_list_sizex<cfg.maxcyclelist) { continue; }

	 lock_cwc(i);
	 clean_part(i);
 	 unlock_cwc(i);
	}
}   

static uint8_t chk_is_pos_fallback(ECM_REQUEST *er, char *reader)
{
	struct s_ecm_answer *ea;
	struct s_reader *fbrdr;
	char fb_reader[64];

	for(ea = er->matching_rdr; ea; ea = ea->next)
	{
		if(ea->reader)
		{
			fbrdr = ea->reader;
			snprintf(fb_reader, sizeof(fb_reader), "%s", ea->reader->label);
			if(!strcmp(reader, fb_reader) && chk_is_fixed_fallback(fbrdr, er))
			{
				cs_log("cyclecheck [check Fixed FB] %s is set as fixed fallback", reader);
				return 1;
			}
		}
	}
	return 0;
}

static inline uint8_t checkECMD5CW(uchar *ecmd5_cw)
{
	int8_t i;
	for(i = 0; i < CS_ECMSTORESIZE; i++)
		if(ecmd5_cw[i]) { return 1; }
	return 0;
}

/*
 * countCWpart is to prevent like this
 * D41A1A08B01DAD7A 0F1D0A36AF9777BD found -> ok
 * E9151917B01DAD7A 0F1D0A36AF9777BD found last -> worng (freeze), but for cwc is ok
 * 7730F59C6653A55E D3822A7F133D3C8C cwc bad -> but cw is right, cwc out of step
 */
static uint8_t countCWpart(ECM_REQUEST *er, struct s_cw_cycle_check *cwc)
{
	uint8_t eo = cwc->nextcyclecw ? 0 : 8;
	int8_t i, ret = 0;
	char cwc_cw[9 * 3];
	char er_cw[9 * 3];

	for(i = 0; i < 8; i++)
	{
		if(cwc->cw[i + eo] == er->cw[i + eo])
		{
			ret++;
		}
	}

	cs_hexdump(0, cwc->cw + eo, 8, cwc_cw, sizeof(cwc_cw));
	cs_hexdump(0, er->cw + eo, 8, er_cw, sizeof(er_cw));
	cs_log_dbg(D_CWC, "cyclecheck [countCWpart] er-cw %s", er_cw);
	cs_log_dbg(D_CWC, "cyclecheck [countCWpart] cw-cw %s", cwc_cw);
	if(ret > cfg.cwcycle_sensitive)
	{
		cs_log("cyclecheck [countCWpart] new cw is to like old one (unused part), sensitive %d, same bytes %d", cfg.cwcycle_sensitive, ret);
	}
	return ret;
}

static uint8_t checkvalidCW(ECM_REQUEST *er)
{
	uint8_t ret = 1;	
	if(chk_is_null_CW(er->cw)) 
	{ er->rc = E_NOTFOUND; }

	if(er->rc == E_NOTFOUND)
	{ return 0; } //wrong  leave the check

	if(checkCWpart(er->cw, 0) && checkCWpart(er->cw, 1))
	{ return 1; } //cw1 and cw2 is filled -> we can check for cwc

	if((!checkCWpart(er->cw, 0) || !checkCWpart(er->cw, 1)) && caid_is_videoguard(er->caid))
	{
		cs_log("CAID: %04X uses obviously half cycle cw's : NO need to check it with CWC! Remove CAID: %04X from CWC Config!", er->caid, er->caid);
		ret = 0;  // cw1 or cw2 is null 
	}

	return ret;
}

static int32_t checkcwcycle_int(ECM_REQUEST *er, char *er_ecmf , char *user, uchar *cw , char *reader, uint8_t cycletime_fr, uint8_t next_cw_cycle_fr, int8_t testcaid)
{

	int8_t i, ret = 6; // ret = 6 no checked
	int8_t cycleok = -1;
	//time_t now = er->tps.time;//time(NULL);
	time_t now = time(NULL);
	uint8_t need_new_entry = 1, upd_entry = 1;
	char cwstr[17 * 3]; //cw to check

	char cwc_ecmf[ECM_FMT_LEN];
	char cwc_md5[17 * 3];
	char cwc_cw[17 * 3];
	char cwc_csp[5 * 3];
	int8_t n = 1, m = 1, k;

	/*for(list = cw_cc_list; list; list = list->next) { // List all Entrys in Log for DEBUG
	    cs_log_dbg(D_CWC, "cyclecheck: [LIST] %04X@%06X:%04X OLD: %i Time: %ld DifftoNow: %ld Stage: %i cw: %s", list->caid, list->provid, list->sid, list->old, list->time, now - list->time, list->stage, cs_hexdump(0, list->cw, 16, cwstr, sizeof(cwstr)));

	}*/

	if(!checkvalidCW(er))
	{ return 3; } //cwc ign	

struct s_cw_cycle_check *cwc;
struct element *test;
struct s_cw_cycle_check currentnodecwc;

	if(!er->tps.time) { cs_ftime(&er->tps); }
	now = er->tps.time;//time(NULL);
	currentnodecwc.caid=er->caid;
	currentnodecwc.provid=er->prid;
	currentnodecwc.sid=er->srvid;
	currentnodecwc.chid=er->chid;
	currentnodecwc.ecmlen=er->ecmlen;
	
	switch (testcaid)
	{
	case 1:
	test=searchelement(tRoot,&currentnodecwc);
	break;
	case 2:
	test=searchelement(tRoot2,&currentnodecwc);
	break;
	case 3:
	test=searchelement(tRoot3,&currentnodecwc);
	break;
	case 4:
	test=searchelement(tRoot4,&currentnodecwc);
	break;
	case 5:
	test=searchelement(tRoot5,&currentnodecwc);
	break;
	case 6:
	test=searchelement(tRoot6,&currentnodecwc);
	break;
	case 7:
	test=searchelement(tRoot7,&currentnodecwc);
	break;
	case 8:
	test=searchelement(tRoot8,&currentnodecwc);
	break;
	case 9:
	test=searchelement(tRoot9,&currentnodecwc);
	break;
	case 10:
	test=searchelement(tRoot10,&currentnodecwc);
	break;
	case 11:
	test=searchelement(tRoot11,&currentnodecwc);
	break;
	case 12:
	test=searchelement(tRoot12,&currentnodecwc);
	break;
	case 13:
	test=searchelement(tRoot13,&currentnodecwc);
	break;
	case 14:
	test=searchelement(tRoot14,&currentnodecwc);
	break;
	case 15:
	test=searchelement(tRoot15,&currentnodecwc);
	break;
	case 16:
	test=searchelement(tRoot16,&currentnodecwc);
	break;
	case 17:
	test=searchelement(tRoot17,&currentnodecwc);
	break;
	case 18:
	test=searchelement(tRoot18,&currentnodecwc);
	break;
	case 19:
	test=searchelement(tRoot19,&currentnodecwc);
	break;
	case 20:
	test=searchelement(tRoot20,&currentnodecwc);
	break;
	case 21:
	test=searchelement(tRoot21,&currentnodecwc);
	break;
	case 22:
	test=searchelement(tRoot22,&currentnodecwc);
	break;
	case 23:
	test=searchelement(tRoot23,&currentnodecwc);
	break;
	case 24:
	test=searchelement(tRoot24,&currentnodecwc);
	break;
	case 25:
	test=searchelement(tRoot25,&currentnodecwc);
	break;
	case 26:
	test=searchelement(tRoot26,&currentnodecwc);
	break;
	case 27:
	test=searchelement(tRoot27,&currentnodecwc);
	break;
	case 28:
	test=searchelement(tRoot28,&currentnodecwc);
	break;
	case 29:
	test=searchelement(tRoot29,&currentnodecwc);
	break;
	case 30:
	test=searchelement(tRoot30,&currentnodecwc);
	break;
	case 31:
	test=searchelement(tRoot31,&currentnodecwc);
	break;
	}
	if (test)
	cwc=test->key;
	else
	{cwc=NULL;}


    if(cwc)
	{
		need_new_entry = 0; // we got a entry for caid/prov/sid so we dont need new one

		cs_hexdump(0, cw, 16, cwstr, sizeof(cwstr)); //checked cw for log

			if (config_enabled(WITH_DEBUG) && ((D_CWC) & cs_dblevel))
			{
			//now we have all data and can leave read lock
			//cs_readunlock(__func__, &cwcycle_lock);

			cs_hexdump(0, cwc->ecm_md5[cwc->cwc_hist_entry].md5, 16, cwc_md5, sizeof(cwc_md5));
			cs_hexdump(0, (void *)&cwc->ecm_md5[cwc->cwc_hist_entry].csp_hash, 4, cwc_csp, sizeof(cwc_csp));
			cs_hexdump(0, cwc->cw, 16, cwc_cw, sizeof(cwc_cw));
			ecmfmt(cwc_ecmf, ECM_FMT_LEN, cwc->caid, 0, cwc->provid, cwc->chid, 0, cwc->sid, cwc->ecmlen, cwc_md5, cwc_csp, cwc_cw, 0, 0, NULL, NULL);
			}
// Cycletime over Cacheex
			if (cfg.cwcycle_usecwcfromce)
			{
				if(cycletime_fr > 0 && next_cw_cycle_fr < 2)
				{
					cs_log_dbg(D_CWC, "cyclecheck [Use Info in Request] Client: %s cycletime: %isek - nextcwcycle: CW%i for %04X@%06X:%04X", user, cycletime_fr, next_cw_cycle_fr, er->caid, er->prid, er->srvid);
					cwc->stage = 3;
					cwc->cycletime = cycletime_fr;
					cwc->nextcyclecw = next_cw_cycle_fr;
					ret = 8;
					if(memcmp(cwc->cw, cw, 16) == 0) //check if the store cw the same like the current
					{
						cs_log_dbg(D_CWC, "cyclecheck [Dump Stored CW] Client: %s EA: %s CW: %s Time: %ld", user, cwc_ecmf, cwc_cw, cwc->time);
						cs_log_dbg(D_CWC, "cyclecheck [Dump CheckedCW] Client: %s EA: %s CW: %s Time: %ld Timediff: %ld", user, er_ecmf, cwstr, now, now - cwc->time);
						if(now - cwc->time >= cwc->cycletime - cwc->dyncycletime)
						{
							cs_log_dbg(D_CWC, "cyclecheck [Same CW but much too late] Client: %s EA: %s CW: %s Time: %ld Timediff: %ld", user, er_ecmf, cwstr, now, now - cwc->time);
							ret = cfg.cwcycle_dropold ? 2 : 4;
						}
						else
						{				
						ret = 4; // Return 4 same CW
						}
						upd_entry = 0;
					}		
					goto OUTCHECK;
				}
			}
//
			if(cwc->stage == 3 && cwc->nextcyclecw < 2 && now - cwc->time < cwc->cycletime * 2 - cwc->dyncycletime - 1)    // Check for Cycle no need to check Entrys others like stage 3
			{
				/*for (k=0; k<15; k++) { // debug md5
				            cs_log_dbg(D_CWC, "cyclecheck [checksumlist[%i]]: ecm_md5: %s csp-hash: %d Entry: %i", k, cs_hexdump(0, cwc->ecm_md5[k].md5, 16, ecm_md5, sizeof(ecm_md5)), cwc->ecm_md5[k].csp_hash, cwc->cwc_hist_entry);
				} */

					// first we check if the store cw the same like the current
					if(memcmp(cwc->cw, cw, 16) == 0)
					{
						cs_log_dbg(D_CWC, "cyclecheck [Dump Stored CW] Client: %s EA: %s CW: %s Time: %ld", user, cwc_ecmf, cwc_cw, cwc->time);
						cs_log_dbg(D_CWC, "cyclecheck [Dump CheckedCW] Client: %s EA: %s CW: %s Time: %ld Timediff: %ld", user, er_ecmf, cwstr, now, now - cwc->time);
						if(now - cwc->time >= cwc->cycletime - cwc->dyncycletime)
						{
							cs_log_dbg(D_CWC, "cyclecheck [Same CW but much too late] Client: %s EA: %s CW: %s Time: %ld Timediff: %ld", user, er_ecmf, cwstr, now, now - cwc->time);
							ret = cfg.cwcycle_dropold ? 2 : 4;
						}
						else
						{				
						ret = 4;  // Return 4 same CW
						}
						upd_entry = 0;
						goto OUTCHECK;
					}

					if(cwc->nextcyclecw == 0)    //CW0 must Cycle
					{
						for(i = 0; i < 8; i++)
						{
							if(cwc->cw[i] == cw[i])
							{
								cycleok = 0; //means CW0 Cycle OK
							}
							else
							{
								cycleok = -1;
								goto OUTCHECK;
							}
						}
					}
					else if(cwc->nextcyclecw == 1)     //CW1 must Cycle
					{
						for(i = 0; i < 8; i++)
						{
							if(cwc->cw[i + 8] == cw[i + 8])
							{
								cycleok = 1; //means CW1 Cycle OK
							}
							else
							{
								cycleok = -1;
								goto OUTCHECK;
							}
						}
					}

					if(cycleok >= 0 && cfg.cwcycle_sensitive && countCWpart(er, cwc) >= cfg.cwcycle_sensitive)  //2,3,4, 0 = off
					{
						cycleok = -2;
					}

				if(cycleok >= 0)
				{
					ret = 0;  // return Code 0 Cycle OK
					if(cycleok == 0)
					{
						cwc->nextcyclecw = 1;
						er->cwc_next_cw_cycle = 1;
						if(cwc->cycletime < 128 && (!(cwc->caid == 0x0100 && cwc->provid == 0x00006A))) // make sure cycletime is lower dez 128 because share over cacheex buf[18] bit 8 is used for cwc_next_cw_cycle
							{ er->cwc_cycletime = cwc->cycletime; }
						cs_log_dbg(D_CWC, "cyclecheck [Valid CW 0 Cycle] Client: %s EA: %s Timediff: %ld Stage: %i Cycletime: %i dyncycletime: %i nextCycleCW = CW%i from Reader: %s", user, er_ecmf, now - cwc->time, cwc->stage, cwc->cycletime, cwc->dyncycletime, cwc->nextcyclecw, reader);
					}
					else if(cycleok == 1)
					{
						cwc->nextcyclecw = 0;
						er->cwc_next_cw_cycle = 0;
						if(cwc->cycletime < 128 && (!(cwc->caid == 0x0100 && cwc->provid == 0x00006A))) // make sure cycletime is lower dez 128 because share over cacheex buf[18] bit 8 is used for cwc_next_cw_cycle
							{ er->cwc_cycletime = cwc->cycletime; }
						cs_log_dbg(D_CWC, "cyclecheck [Valid CW 1 Cycle] Client: %s EA: %s Timediff: %ld Stage: %i Cycletime: %i dyncycletime: %i nextCycleCW = CW%i from Reader: %s", user, er_ecmf, now - cwc->time, cwc->stage, cwc->cycletime, cwc->dyncycletime, cwc->nextcyclecw, reader);
					}
					cs_log_dbg(D_CWC, "cyclecheck [Dump Stored CW] Client: %s EA: %s CW: %s Time: %ld", user, cwc_ecmf, cwc_cw, cwc->time);
					cs_log_dbg(D_CWC, "cyclecheck [Dump CheckedCW] Client: %s EA: %s CW: %s Time: %ld Timediff: %ld", user, er_ecmf, cwstr, now, now - cwc->time);
				}
				else
				{

					for(k = 0; k < 15; k++)  // check for old ECMs
					{
#ifdef CS_CACHEEX
						if((checkECMD5CW(er->ecmd5) && checkECMD5CW(cwc->ecm_md5[k].md5) && !(memcmp(er->ecmd5, cwc->ecm_md5[k].md5, sizeof(er->ecmd5)))) || (er->csp_hash && cwc->ecm_md5[k].csp_hash && er->csp_hash == cwc->ecm_md5[k].csp_hash))
#else
						if((memcmp(er->ecmd5, cwc->ecm_md5[k].md5, sizeof(er->ecmd5))) == 0)
#endif
						{
							cs_log_dbg(D_CWC, "cyclecheck [OLD] [CheckedECM] Client: %s EA: %s", user, er_ecmf);
							cs_hexdump(0, cwc->ecm_md5[k].md5, 16, cwc_md5, sizeof(cwc_md5));
							cs_hexdump(0, (void *)&cwc->ecm_md5[k].csp_hash, 4, cwc_csp, sizeof(cwc_csp));
							cs_log_dbg(D_CWC, "cyclecheck [OLD] [Stored ECM] Client: %s EA: %s.%s", user, cwc_md5, cwc_csp);
							if(!cfg.cwcycle_dropold && !memcmp(cwc->ecm_md5[k].cw, cw, 16))
								{ ret = 4; }
							else
								{ ret = 2; } // old ER
							upd_entry = 0;
							goto OUTCHECK;
						}
					}
					if(!upd_entry) {goto OUTCHECK; }
					if(cycleok == -2)
						{ cs_log_dbg(D_CWC, "cyclecheck [ATTENTION!! NON Valid CW] Client: %s EA: %s Timediff: %ld Stage: %i Cycletime: %i dyncycletime: %i nextCycleCW = CW%i from Reader: %s", user, er_ecmf, now - cwc->time, cwc->stage, cwc->cycletime, cwc->dyncycletime, cwc->nextcyclecw, reader); }
					else
						{ cs_log_dbg(D_CWC, "cyclecheck [ATTENTION!! NON Valid CW Cycle] NO CW Cycle detected! Client: %s EA: %s Timediff: %ld Stage: %i Cycletime: %i dyncycletime: %i nextCycleCW = CW%i from Reader: %s", user, er_ecmf, now - cwc->time, cwc->stage, cwc->cycletime, cwc->dyncycletime, cwc->nextcyclecw, reader); }
					cs_log_dbg(D_CWC, "cyclecheck [Dump Stored CW] Client: %s EA: %s CW: %s Time: %ld", user, cwc_ecmf, cwc_cw, cwc->time);
					cs_log_dbg(D_CWC, "cyclecheck [Dump CheckedCW] Client: %s EA: %s CW: %s Time: %ld Timediff: %ld", user, er_ecmf, cwstr, now, now - cwc->time);
					ret = 1; // bad cycle
					upd_entry = 0;
					if(cfg.cwcycle_allowbadfromffb)
					{
						if(chk_is_pos_fallback(er, reader))
								{
									ret = 5;
									cwc->stage = 4;
									upd_entry = 1;
									cwc->nextcyclecw = 2;
									goto OUTCHECK;
								}
							}
					goto OUTCHECK;
				}
			}
			else
			{
				if(cwc->stage == 3)
				{
					if(cfg.keepcycletime > 0 && now - cwc->time < cfg.keepcycletime * 60)    // we are in keepcycletime window
					{
						cwc->stage++;   // go to stage 4
						cs_log_dbg(D_CWC, "cyclecheck [Set Stage 4] for Entry: %s Cycletime: %i -> Entry too old but in keepcycletime window - no cycletime learning - only check which CW must cycle", cwc_ecmf, cwc->cycletime);
					}
					else
					{
						cwc->stage--; // go one stage back, we are not in keepcycletime window
						cs_log_dbg(D_CWC, "cyclecheck [Back to Stage 2] for Entry: %s Cycletime: %i -> new cycletime learning", cwc_ecmf, cwc->cycletime);
					}
					memset(cwc->cw, 0, sizeof(cwc->cw)); //fake cw for stage 2/4
					ret = 3;
					cwc->nextcyclecw = 2;
				}
			}
			if(upd_entry)    //  learning stages
			{
//				if(now > cwc->locktime)
				if(comp_timeb(&er->tps,&cwc->locktime1)>0) 
				{
					int16_t diff = now - cwc->time - cwc->cycletime;
					if(cwc->stage <= 0)    // stage 0 is passed; we update the cw's and time and store cycletime
					{
						//if(cwc->cycletime == now - cwc->time)    // if we got a stable cycletime we go to stage 1
                        if(diff > -2 && diff < 2)    // if we got a stable cycletime we go to stage 1
                        {
                            cwc->cycletime = now - cwc->time;	
							cs_log_dbg(D_CWC, "cyclecheck [Set Stage 1] %s Cycletime: %i Lockdiff: %ld", cwc_ecmf, cwc->cycletime, now - cwc->locktime);
							cwc->stage++; // increase stage
						}
						else
						{
							cs_log_dbg(D_CWC, "cyclecheck [Stay on Stage 0] %s Cycletime: %i -> no constant CW-Change-Time", cwc_ecmf, cwc->cycletime);
						}

					}
					else if(cwc->stage == 1)     // stage 1 is passed; we update the cw's and time and store cycletime
					{
                        // if(cwc->cycletime == now - cwc->time)    // if we got a stable cycletime we go to stage 2
                        if(diff > -2 && diff < 2)    // if we got a stable cycletime we go to stage 2
                        {
						 	 cwc->cycletime = now - cwc->time;
							 cs_log_dbg(D_CWC, "cyclecheck [Set Stage 2] %s Cycletime: %i Lockdiff: %ld", cwc_ecmf, cwc->cycletime, now - cwc->locktime);
 							 cwc->stage++; // increase stage
						}
						else
						{
							cs_log_dbg(D_CWC, "cyclecheck [Back to Stage 0] for Entry %s Cycletime: %i -> no constant CW-Change-Time", cwc_ecmf, cwc->cycletime);
							cwc->stage--;
						}
					}
					else if(cwc->stage == 2)     // stage 2 is passed; we update the cw's and compare cycletime
					{
                        // if(cwc->cycletime == now - cwc->time && cwc->cycletime > 0)    // if we got a stable cycletime we go to stage 3
 	                    if(diff > -2 && diff < 2 && cwc->cycletime > 0)    // if we got a stable cycletime we go to stage 3
 	                    {
 	                        cwc->cycletime = now - cwc->time;
							n = memcmp(cwc->cw, cw, 8);
							m = memcmp(cwc->cw + 8, cw + 8, 8);
							if(n == 0)
							{
								cwc->nextcyclecw = 1;
							}
							if(m == 0)
							{
								cwc->nextcyclecw = 0;
							}
							if(n == m || !checkECMD5CW(cw)) { cwc->nextcyclecw = 2; }  //be sure only one cw part cycle and is valid
							if(cwc->nextcyclecw < 2)
							{
								cs_log_dbg(D_CWC, "cyclecheck [Set Stage 3] %s Cycletime: %i Lockdiff: %ld nextCycleCW = CW%i", cwc_ecmf, cwc->cycletime, now - cwc->locktime, cwc->nextcyclecw);
								cs_log_dbg(D_CWC, "cyclecheck [Set Cycletime %i] for Entry: %s -> now we can check CW's", cwc->cycletime, cwc_ecmf);
								cwc->stage = 3; // increase stage
							}
							else
							{
								cs_log_dbg(D_CWC, "cyclecheck [Back to Stage 1] for Entry %s Cycletime: %i -> no CW-Cycle in Learning Stage", cwc_ecmf, cwc->cycletime);  // if a server asked only every twice ECM we got a stable cycletime*2 ->but thats wrong
								cwc->stage = 1;
							}

						}
						else
						{

							cs_log_dbg(D_CWC, "cyclecheck [Back to Stage 1] for Entry %s Cycletime: %i -> no constant CW-Change-Time", cwc_ecmf, cwc->cycletime);
							cwc->stage = 1;
						}
					}
					else if(cwc->stage == 4)	// we got a early learned cycletime.. use this cycletime and check only which cw cycle 
					{
						n = memcmp(cwc->cw, cw, 8);
						m = memcmp(cwc->cw + 8, cw + 8, 8);
						if(n == 0)
						{
							cwc->nextcyclecw = 1;
						}
						if(m == 0)
						{
							cwc->nextcyclecw = 0;
						}
						if(n == m || !checkECMD5CW(cw)) { cwc->nextcyclecw = 2; }  //be sure only one cw part cycle and is valid
						if(cwc->nextcyclecw < 2)
						{
							cs_log_dbg(D_CWC, "cyclecheck [Back to Stage 3] %s Cycletime: %i Lockdiff: %ld nextCycleCW = CW%i", cwc_ecmf, cwc->cycletime, now - cwc->locktime, cwc->nextcyclecw);
							cs_log_dbg(D_CWC, "cyclecheck [Set old Cycletime %i] for Entry: %s -> now we can check CW's", cwc->cycletime, cwc_ecmf);
							cwc->stage = 3; // go back to stage 3
						}
						else
						{
							cs_log_dbg(D_CWC, "cyclecheck [Stay on Stage %d] for Entry %s Cycletime: %i no cycle detect!", cwc->stage, cwc_ecmf, cwc->cycletime);
							if (cwc->stage4_repeat > 12) 
							{ 
								cwc->stage = 1;
								cs_log_dbg(D_CWC, "cyclecheck [Back to Stage 1] too much cyclefailure, maybe cycletime not correct %s Cycletime: %i Lockdiff: %ld nextCycleCW = CW%i", cwc_ecmf, cwc->cycletime, now - cwc->locktime, cwc->nextcyclecw);							
							} 
						}
						cwc->stage4_repeat++;
						ret = ret == 3 ? 3 : 7; // IGN for first stage4 otherwise LEARN
					}
					if(cwc->stage == 3)
					{
						cwc->locktime = 0;
						cwc->locktime1.time = 0;
						cwc->locktime1.millitm = 0; 
						cwc->stage4_repeat = 0;
					}
					else
					{
						if(cwc->stage < 3) { cwc->cycletime = now - cwc->time; }
						cwc->locktime = now + (get_fallbacktimeout(cwc->caid) / 1000);
						cwc->locktime1 = er->tps;
						add_ms_to_timeb_diff(&cwc->locktime1,get_fallbacktimeout(er->caid)); 						
					}
				}
				else if(cwc->stage != 3)
				{
					cs_log_dbg(D_CWC, "cyclecheck [Ignore this EA] for LearningStages because of locktime EA: %s Lockdiff: %ld", cwc_ecmf, now - cwc->locktime);
					upd_entry = 0;
				}

				if(cwc->stage == 3)     // we stay in Stage 3 so we update only time and cw
				{
					if(now - cwc->time > cwc->cycletime)
					{
						cwc->dyncycletime = now - cwc->time - cwc->cycletime;
					}
					else
					{
						cwc->dyncycletime = 0;
					}
				}
			}
		}

  OUTCHECK:
	if(need_new_entry)
	{
	   int16_t cw_cc_list_size;
	   cw_cc_list_size = cache_size_cwc_selected(testcaid);

		if(cw_cc_list_size <= cfg.maxcyclelist)    //only add when we have space
		{
			struct s_cw_cycle_check *new = NULL;
	if(cs_malloc(&new, sizeof(struct s_cw_cycle_check)))    // store cw on top in cyclelist
	{
				memcpy(new->cw, cw, sizeof(new->cw));
				// csp cache got no ecm and no md5 hash
				memcpy(new->ecm_md5[0].md5, er->ecmd5, sizeof(er->ecmd5));
#ifdef CS_CACHEEX
				new->ecm_md5[0].csp_hash = er->csp_hash; // we got no ecm_md5 so CSP-Hash could be necessary
#else
				new->ecm_md5[0].csp_hash = 0; //fake CSP-Hash we got a ecm_md5 so CSP-Hash is not necessary
#endif
				memcpy(new->ecm_md5[0].cw, cw, sizeof(new->cw));
				new->ecmlen = er->ecmlen;
//				new->cwc_hist_entry = 0;  //done by cs_malloc
				new->caid = er->caid;
				new->provid = er->prid;
				new->sid = er->srvid;
				new->chid = er->chid;
				new->time = now;
				new->locktime = now + (get_fallbacktimeout(er->caid) / 1000);
				new->dyncycletime = 0; // to react of share timings
// cycletime over Cacheex
				new->stage = (cfg.cwcycle_usecwcfromce && cycletime_fr > 0 && next_cw_cycle_fr < 2) ? 3 : 0;
				new->cycletime = (cfg.cwcycle_usecwcfromce && cycletime_fr > 0 && next_cw_cycle_fr < 2) ? cycletime_fr : 99;
				new->nextcyclecw = (cfg.cwcycle_usecwcfromce && cycletime_fr > 0 && next_cw_cycle_fr < 2) ? next_cw_cycle_fr : 2; //2=we dont know which next cw Cycle;  0= next cw Cycle CW0; 1= next cw Cycle CW1;
				ret = (cycletime_fr > 0 && next_cw_cycle_fr < 2) ? 8 : 6;
				switch (testcaid)
				{
				case 1:
				tRoot = insertcwc(tRoot,new);
				break;
				case 2:
				tRoot2 = insertcwc(tRoot2,new);
				break;
				case 3:
				tRoot3 = insertcwc(tRoot3,new);
				break;
				case 4:
				tRoot4 = insertcwc(tRoot4,new);
				break;
				case 5:
				tRoot5 = insertcwc(tRoot5,new);
				break;
				case 6:
				tRoot6 = insertcwc(tRoot6,new);
				break;
				case 7:
				tRoot7 = insertcwc(tRoot7,new);
				break;
				case 8:
				tRoot8 = insertcwc(tRoot8,new);
				break;
				case 9:
				tRoot9 = insertcwc(tRoot9,new);
				break;
				case 10:
				tRoot10 = insertcwc(tRoot10,new);
				break;
				case 11:
				tRoot11 = insertcwc(tRoot11,new);
				break;
				case 12:
				tRoot12 = insertcwc(tRoot12,new);
				break;
				case 13:
				tRoot13 = insertcwc(tRoot13,new);
				break;
				case 14:
				tRoot14 = insertcwc(tRoot14,new);
				break;
				case 15:
				tRoot15 = insertcwc(tRoot15,new);
				break;
				case 16:
				tRoot16 = insertcwc(tRoot16,new);
				break;
				case 17:
				tRoot17 = insertcwc(tRoot17,new);
				break;
				case 18:
				tRoot18 = insertcwc(tRoot18,new);
				break;
				case 19:
				tRoot19 = insertcwc(tRoot19,new);
				break;
				case 20:
				tRoot20 = insertcwc(tRoot20,new);
				break;
				case 21:
				tRoot21 = insertcwc(tRoot21,new);
				break;
				case 22:
				tRoot22 = insertcwc(tRoot22,new);
				break;
				case 23:
				tRoot23 = insertcwc(tRoot23,new);
				break;
				case 24:
				tRoot24 = insertcwc(tRoot24,new);
				break;
				case 25:
				tRoot25 = insertcwc(tRoot25,new);
				break;
				case 26:
				tRoot26 = insertcwc(tRoot26,new);
				break;
				case 27:
				tRoot27 = insertcwc(tRoot27,new);
				break;
				case 28:
				tRoot28 = insertcwc(tRoot28,new);
				break;
				case 29:
				tRoot29 = insertcwc(tRoot29,new);
				break;
				case 30:
				tRoot30 = insertcwc(tRoot30,new);
				break;
				case 31:
				tRoot31 = insertcwc(tRoot31,new);
				break;
				}
	   
	   switch(testcaid)
  	   {
		case 1: cw_cc_list_size1++; 
		break;
		case 2: cw_cc_list_size2++;
		break;
		case 3: cw_cc_list_size3++;
		break;
		case 4: cw_cc_list_size4++;
		break;
		case 5: cw_cc_list_size5++;
		break;
		case 6: cw_cc_list_size6++;
	 	break;
		case 7: cw_cc_list_size7++;
	 	break;
	 	case 8: cw_cc_list_size8++;
	 	break;
	 	case 9: cw_cc_list_size9++;
	 	break;
		case 10: cw_cc_list_size10++;
	 	break;
		case 11: cw_cc_list_size11++;
	 	break;
		case 12: cw_cc_list_size12++;
	 	break;
		case 13: cw_cc_list_size13++;
	 	break;
		case 14: cw_cc_list_size14++;
	 	break;
		case 15: cw_cc_list_size15++;
	 	break;
		case 16: cw_cc_list_size16++;
	 	break;
		case 17: cw_cc_list_size17++;
	 	break;
		case 18: cw_cc_list_size18++;
	 	break;
		case 19: cw_cc_list_size19++;
	 	break;
		case 20: cw_cc_list_size20++;
	 	break;
		case 21: cw_cc_list_size21++;
	 	break;
		case 22: cw_cc_list_size22++;
	 	break;
		case 23: cw_cc_list_size23++;
	 	break;
		case 24: cw_cc_list_size24++;
	 	break;
		case 25: cw_cc_list_size25++;
	 	break;
		case 26: cw_cc_list_size26++;
	 	break;
		case 27: cw_cc_list_size27++;
	 	break;
		case 28: cw_cc_list_size28++;
	 	break;
		case 29: cw_cc_list_size29++;
	 	break;
		case 30: cw_cc_list_size30++;
	 	break;
		case 31: cw_cc_list_size31++;
	 	break;
	   }

				cs_log_dbg(D_CWC, "cyclecheck [Store New Entry] %s Time: %ld Stage: %i Cycletime: %i Locktime: %ld", er_ecmf, new->time, new->stage, new->cycletime, new->locktime);
	}
		}
		else
		{
			cs_log("cyclecheck [Store New Entry] Max List arrived -> dont store new Entry list_size: %i, mcl: %i", cw_cc_list_size, cfg.maxcyclelist);
		}
	}
	else if(upd_entry && cwc)
	{
		//cwc->prev = cwc->next = NULL;
		//cwc->next = NULL;
		memcpy(cwc->cw, cw, sizeof(cwc->cw));
		cwc->time = now;
		cwc->cwc_hist_entry++;
		if(cwc->cwc_hist_entry > 14)     //ringbuffer for md5
		{
			cwc->cwc_hist_entry = 0;
		}
		// csp cache got no ecm and no md5 hash
		memcpy(cwc->ecm_md5[cwc->cwc_hist_entry].md5, er->ecmd5, sizeof(cwc->ecm_md5[0].md5));
#ifdef CS_CACHEEX
		cwc->ecm_md5[cwc->cwc_hist_entry].csp_hash = er->csp_hash;
#else
		cwc->ecm_md5[cwc->cwc_hist_entry].csp_hash = 0; //fake CSP-Hash for logging
#endif
		memcpy(cwc->ecm_md5[cwc->cwc_hist_entry].cw, cw, sizeof(cwc->cw));
		cwc->ecmlen = er->ecmlen;

		cs_log_dbg(D_CWC, "cyclecheck [Update Entry and add on top] %s Time: %ld Stage: %i Cycletime: %i", er_ecmf, cwc->time, cwc->stage, cwc->cycletime);
	}
	return ret;
}

static void count_ok(struct s_client *client)
{
	if(client)
	{
		client->cwcycledchecked++;
		client->cwcycledok++;
	}
	if(client && client->account)
	{
		client->account->cwcycledchecked++;
		client->account->cwcycledok++;
	}
}

static void count_nok(struct s_client *client)
{
	if(client)
	{
		client->cwcycledchecked++;
		client->cwcyclednok++;
	}
	if(client && client->account)
	{
		client->account->cwcycledchecked++;
		client->account->cwcyclednok++;
	}
}

static void count_ign(struct s_client *client)
{
	if(client)
	{
		client->cwcycledchecked++;
		client->cwcycledign++;
	}
	if(client && client->account)
	{
		client->account->cwcycledchecked++;
		client->account->cwcycledign++;
	}
}

uint8_t checkcwcycle(struct s_client *client, ECM_REQUEST *er, struct s_reader *reader, uchar *cw, int8_t rc, uint8_t cycletime_fr, uint8_t next_cw_cycle_fr)
{

	if(!cfg.cwcycle_check_enable)
		{ return 3; }
	if(client && client->account && client->account->cwc_disable)
		{ return 3; }
	//  if (!(rc == E_FOUND) && !(rc == E_CACHEEX))
	if(rc >= E_NOTFOUND)
		{ return 2; }
	if(!cw || !er)
		{ return 2; }
	if(!(chk_ctab_ex(er->caid, &cfg.cwcycle_check_caidtab)))  // dont check caid not in list
		{ return 1; } // no match leave the check
	if(is_halfCW_er(er))
		{ return 1; } // half cw cycle, checks are done in ecm-handler

	memcpy(er->cw, cw, 16);
	char er_ecmf[ECM_FMT_LEN];
	format_ecm(er, er_ecmf, ECM_FMT_LEN);

	char c_reader[64];
	char user[64];

	if(!streq(username(client), "NULL"))
		{ snprintf(user, sizeof(user), "%s", username(client)); }
	else
		{ snprintf(user, sizeof(user), "---"); }

	if(reader)
		{ snprintf(c_reader, sizeof(c_reader), "%s", reader->label); }
	else
		{ snprintf(c_reader, sizeof(c_reader), "cache"); }


	cs_log_dbg(D_CWC | D_TRACE, "cyclecheck EA: %s rc: %i reader: %s", er_ecmf, rc, c_reader);

	int8_t testcaid=get_ecmofs_cwc(er);
	lock_cwc(testcaid);
	int8_t test = checkcwcycle_int(er, er_ecmf, user, cw, c_reader, cycletime_fr, next_cw_cycle_fr, testcaid);
	unlock_cwc(testcaid);
	
	switch(test)
	{

	case 0: // CWCYCLE OK
		count_ok(client);
		snprintf(er->cwc_msg_log, sizeof(er->cwc_msg_log), "cwc OK");
		break;

	case 1: // CWCYCLE NOK
		count_nok(client);
		snprintf(er->cwc_msg_log, sizeof(er->cwc_msg_log), "cwc NOK");
		if(cfg.onbadcycle > 0)    // ignore ECM Request
		{
			cs_log("cyclecheck [Bad CW Cycle] for: %s %s from: %s -> drop cw (ECM Answer)", user, er_ecmf, c_reader); //D_CWC| D_TRACE
			return 0;
		}
		else      // only logging
		{
			cs_log("cyclecheck [Bad CW Cycle] for: %s %s from: %s -> do nothing", user, er_ecmf, c_reader);//D_CWC| D_TRACE
			break;
		}

	case 2: // ER to OLD
		count_nok(client);
		snprintf(er->cwc_msg_log, sizeof(er->cwc_msg_log), "cwc NOK(old)");
		cs_log("cyclecheck [Bad CW Cycle] for: %s %s from: %s -> ECM Answer is too OLD -> drop cw (ECM Answer)", user, er_ecmf, c_reader);//D_CWC| D_TRACE
		return 0;

	case 3: // CycleCheck ignored (stage 3 to stage 4)
		count_ign(client);
		snprintf(er->cwc_msg_log, sizeof(er->cwc_msg_log), "cwc IGN");
		break;

	case 4: // same CW
		cs_log_dbg(D_CWC, "cyclecheck [Same CW] for: %s %s -> same CW detected from: %s -> do nothing ", user, er_ecmf, c_reader);
		break;

	case 5: //answer from fixed Fallbackreader with Bad Cycle
		count_nok(client);
		snprintf(er->cwc_msg_log, sizeof(er->cwc_msg_log), "cwc NOK but IGN (fixed FB)");
		cs_log("cyclecheck [Bad CW Cycle] for: %s %s from: %s -> But Ignored because of answer from Fixed Fallback Reader", user, er_ecmf, c_reader);
		break;

	case 6: // not checked ( learning Stages Cycletime and CWCycle Stage < 3)
	case 7: // not checked ( learning Stages only CWCycle Stage 4)
		snprintf(er->cwc_msg_log, sizeof(er->cwc_msg_log), "cwc LEARN");
		break;

	case 8: // use Cyclecheck from CE Source
		count_ok(client);
		snprintf(er->cwc_msg_log, sizeof(er->cwc_msg_log), "cwc OK(CE)");
		break;

	case 9: // CWCYCLE NOK without counting
		snprintf(er->cwc_msg_log, sizeof(er->cwc_msg_log), "cwc NOK");
		if(cfg.onbadcycle > 0)    // ignore ECM Request
		{
			cs_log("cyclecheck [Bad CW Cycle already Counted] for: %s %s from: %s -> drop cw (ECM Answer)", user, er_ecmf, c_reader); 
			return 0;
		}
		else      // only logging
		{
			cs_log("cyclecheck [Bad CW Cycle already Counted] for: %s %s from: %s -> do nothing", user, er_ecmf, c_reader);
			break;
		}

	}
	return 1;
}


/*
 *
 */

#endif
