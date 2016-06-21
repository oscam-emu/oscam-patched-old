#include "globals.h"
#include "reader-dre-st20.h"

#define IPTR 0
#define WPTR 1
#define AREG 2
#define BREG 3
#define CREG 4

#define FLASHS	0x7FE00000
#define FLASHE	0x7FFFFFFF
#define RAMS	0x40000000
#define RAME	0x401FFFFF
#define IRAMS	0x80000000
#define IRAME	0x800017FF

#define ERR_ILL_OP -1
#define ERR_CNT    -2

// ----------------------------------------------------------------

#define STACKMAX  16
#define STACKMASK (STACKMAX-1)

typedef struct 
{
  uint32_t Iptr, Wptr;
  uint8_t *flash, *ram;
  uint32_t flashSize, ramSize;
  int sptr, stack[STACKMAX];
  uint8_t iram[0x1800];
  int invalid;
  int verbose;
} st20_context_t;


static void st20_set_flash(st20_context_t *ctx, uint8_t *m, int len);
static void st20_set_ram(st20_context_t *ctx, uint8_t *m, int len);
static void st20_init(st20_context_t *ctx, uint32_t IPtr, uint32_t WPtr, int verbose);
static void st20_free(st20_context_t *ctx);

static void st20_set_call_frame(st20_context_t *ctx, uint32_t raddr, int p1, int p2, int p3);


static uint32_t st20_get_reg(st20_context_t *ctx, int reg);
static void st20_set_reg(st20_context_t *ctx, int reg, uint32_t val);
static uint8_t st20_rbyte(st20_context_t *ctx, uint32_t off);
static void st20_wbyte(st20_context_t *ctx, uint32_t off, uint8_t val);
static uint32_t st20_rword(st20_context_t *ctx, uint32_t off);
static void st20_wword(st20_context_t *ctx, uint32_t off, uint32_t val);

#define INVALID_VALUE	0xCCCCCCCC
#define ERRORVAL		0xDEADBEEF

#define MININT			0x7FFFFFFF
#define MOSTPOS			0x7FFFFFFF
#define MOSTNEG			0x80000000


#define POP() ctx->stack[(ctx->sptr++)&STACKMASK]
#define PUSH(v) do { int32_t __v=(v); ctx->stack[(--ctx->sptr)&STACKMASK]=__v; } while(0)
#define DROP(n) ctx->sptr+=n

#define AAA ctx->stack[ctx->sptr&STACKMASK]
#define BBB ctx->stack[(ctx->sptr+1)&STACKMASK]
#define CCC ctx->stack[(ctx->sptr+2)&STACKMASK]

#define GET_OP()        operand|=op1&0x0F
#define CLEAR_OP()      operand=0
#define JUMP(x)         ctx->Iptr+=(x)
#define POP64()         ({ uint32_t __b=POP(); ((uint64_t)POP()<<32)|__b; })
#define PUSHPOP(op,val) do { int32_t __a=val; AAA op##= (__a); } while(0)

#define RB(off) st20_rbyte(ctx, off)
#define RW(off) st20_rword(ctx, off)
#define WW(off,val) st20_wword(ctx, off, val)

static uint32_t st20_get_reg(st20_context_t *ctx, int32_t reg)
{
	switch(reg) 
	{
		case IPTR: return ctx->Iptr;
		case WPTR: return ctx->Wptr;
		case AREG: return AAA;
		case BREG: return BBB;
		case CREG: return CCC;
	}
	return 0;
}

static void st20_set_reg(st20_context_t *ctx, int32_t reg, uint32_t val)
{
	switch(reg)
	{
		case IPTR: ctx->Iptr = val; return;
		case WPTR: ctx->Wptr = val; return;
		case AREG: AAA=val; return;
		case BREG: BBB=val; return;
		case CREG: CCC=val; return;
	}
}

static uint8_t *st20_addr(st20_context_t *ctx, uint32_t off)
{
	if(off >= FLASHS && off <= FLASHE)
	{
		return &ctx->flash[off - FLASHS];
	}
	else if(off >= RAMS && off <= RAME)
	{
		return &ctx->ram[off - RAMS];
	}
	else if(off >= IRAMS && off <= IRAME)
		return &ctx->iram[off - IRAMS];

	ctx->invalid = ERRORVAL;
	return (uint8_t *) &ctx->invalid;
}

static uint32_t st20_rword(st20_context_t *ctx, uint32_t off)
{
	uint8_t *temp;
	temp = st20_addr(ctx, off);
	
	return ((temp[3]<<24) | (temp[2]<<16) | (temp[1]<<8) | temp[0]);
}

static uint16_t st20_rshort(st20_context_t *ctx, uint32_t off)
{
	uint8_t *temp;
	temp = st20_addr(ctx, off);
	
	return ((temp[0]<<8) | temp[1]);
}

static uint8_t st20_rbyte(st20_context_t *ctx, uint32_t off)
{
	return *st20_addr(ctx, off);
}

static void st20_wword(st20_context_t *ctx, uint32_t off, uint32_t val)
{
	uint8_t *temp;
	temp = st20_addr(ctx, off);
	temp[3] = (val >> 24) & 0xFF;
	temp[2] = (val >> 16) & 0xFF;
	temp[1] = (val >> 8) & 0xFF;
	temp[0] = val & 0xFF;
}

static void st20_wbyte(st20_context_t *ctx, uint32_t off, uint8_t val)
{
	uint8_t *temp;
	temp = st20_addr(ctx, off);
	temp[0] = val;
}

static int32_t st20_decode(st20_context_t *ctx, int32_t count)
{
	int32_t operand = 0;
	CLEAR_OP();
	while(ctx->Iptr != 0)
	{
		int32_t a, op1 = RB(ctx->Iptr++);
		GET_OP();
		switch(op1 >> 4)
		{
			case 0x0: // j / jump
				JUMP(operand);
				CLEAR_OP();
				break;
			case 0x1: // ldlp
				PUSH(ctx->Wptr + (operand * 4));
				CLEAR_OP();
				break;
			case 0x2: // positive prefix
				operand <<= 4;
				break;
			case 0x3: // ldnl
				AAA=RW(AAA + (operand * 4));
				CLEAR_OP();
				break;
			case 0x4: // ldc
				PUSH(operand);
				CLEAR_OP();
				break;
			case 0x5: // ldnlp
				PUSHPOP(+, operand * 4);
				CLEAR_OP();
				break;
			case 0x6: // negative prefix
				operand = (~operand) << 4;
				break;
			case 0x7: // ldl
				PUSH(RW(ctx->Wptr + (operand * 4)));
				CLEAR_OP();
				break;
			case 0x8: // adc
				PUSHPOP(+, operand);
				CLEAR_OP();
				break;
			case 0x9: // call
				ctx->Wptr -= 16;
				WW(ctx->Wptr, ctx->Iptr); WW(ctx->Wptr + 4, POP()); WW(ctx->Wptr + 8, POP()); WW(ctx->Wptr + 12, POP());
				PUSH(ctx->Iptr);
				JUMP(operand);
				CLEAR_OP();
				break;
			case 0xA: // cj / conditional jump
				if(AAA) { DROP(1); } else { JUMP(operand); }
				CLEAR_OP();
				break;
			case 0xB: // ajw / adjust workspace
				ctx->Wptr += operand * 4;
				CLEAR_OP();
				break;
			case 0xC: // eqc / equals constant
				AAA = (operand == AAA ? 1 : 0);
				CLEAR_OP();
				break;
			case 0xD: // stl
				WW(ctx->Wptr + (operand * 4), POP());
				CLEAR_OP();
				break;
			case 0xE: // stnl
				a = POP(); WW(a + (operand * 4), POP());
				CLEAR_OP();
				break;
			case 0xF: // opr (secondary ins)
				switch(operand)
				{
					case  0x00: a = AAA; AAA = BBB; BBB = a; break;
					case  0x01: AAA = RB(AAA); break;
					case  0x02: PUSHPOP(+, POP()); break;
					case  0x04: PUSHPOP(-, POP()); break;
					case  0x05: PUSHPOP(+, POP()); break;
					case  0x06: a = AAA; AAA = ctx->Iptr; ctx->Iptr = a; break;
					case  0x08: PUSHPOP(*, POP()); break;
					case  0x09: a=POP(); AAA = (AAA > a); break;
					case  0x0A: a=POP(); AAA = a + (AAA * 4); break;
					case  0x0C: PUSHPOP(-, POP()); break;
					case  0x1A: { a = POP(); uint64_t ll = POP64(); PUSH(ll % (uint32_t)a); PUSH(ll / (uint32_t)a); } break;
					case  0x1B: PUSHPOP(+, ctx->Iptr); break;
					case  0x1D: CCC = BBB; BBB = (AAA >= 0 ? 0 : -1); break;
					case  0x1F: PUSHPOP(%, POP()); break;
					case  0x20: ctx->Iptr = RW(ctx->Wptr); ctx->Wptr = ctx->Wptr + 16; break;
					case  0x2C: PUSHPOP(/, POP()); break;
					case  0x30: break;
					case  0x32: AAA =~ AAA; break;
					case  0x33: PUSHPOP(^, POP()); break;
					case  0x34: PUSHPOP(*, 4); break;
					case  0x35: { a = POP(); uint64_t ll = POP64() >> a; PUSH((ll >> 32) & 0xFFFFFFFF); PUSH(ll & 0xFFFFFFFF); } break;
					case  0x36: { a = POP(); uint64_t ll = POP64() << a; PUSH((ll >> 32) & 0xFFFFFFFF); PUSH(ll & 0xFFFFFFFF); } break;
					case  0x3B: a = POP(); st20_wbyte(ctx, a, POP()); break;
					case  0x3F: a = POP(); PUSH(a & 3); PUSH((uint32_t)a >> 2); break;
					case  0x40: a = POP(); AAA = (uint32_t)AAA >> a; break;
					case  0x41: a = POP(); AAA = (uint32_t)AAA << a; break;
					case  0x42: PUSH(MOSTNEG); break;
					case  0x46: PUSHPOP(&, POP()); break;
					case  0x4A: { a = POP(); int32_t b = POP(); int32_t c = POP(); while(a--) st20_wbyte(ctx, b++, st20_rbyte(ctx, c++)); } break;
					case  0x4B: PUSHPOP(|, POP()); break;
					case  0x53: PUSHPOP(*, POP()); break;
					case  0x5A: PUSH(AAA); break;
					case  0x5F: a = POP(); AAA = ((uint32_t)AAA > (uint32_t)a); break;
					case  0x78: { a = POP(); int32_t b = POP(); int32_t bb = 0; while(a--){bb <<= 1; bb |= b & 1; b >>= 1;} PUSH(bb);} break;
					case  0xCA: AAA = st20_rshort(ctx, AAA); break;
					default: 
					cs_log("[icg] unknown opcode %X", operand);
					return ERR_ILL_OP;
				}
				CLEAR_OP();
				break;
			}
		if(--count <= 0 && operand == 0) return ERR_CNT;
	}
	return 0;
}

static void st20_set_flash(st20_context_t *ctx, uint8_t *m, int32_t len)
{
	if(ctx->flash) free(ctx->flash);
	ctx->flash = malloc(len);
	if(ctx->flash && m) memcpy(ctx->flash, m, len);
	else memset(ctx->flash, 0, len);
	ctx->flashSize = len;
}

static void st20_set_ram(st20_context_t *ctx, uint8_t *m, int32_t len)
{
	if(ctx->ram) free(ctx->ram);
	ctx->ram = malloc(len);
	if(ctx->ram && m) memcpy(ctx->ram, m, len);
	else memset(ctx->ram, 0, len);
	ctx->ramSize = len;
}

static void st20_init(st20_context_t *ctx, uint32_t IPtr, uint32_t WPtr, int32_t verbose)
{
	ctx->Wptr = WPtr; ctx->Iptr = IPtr;
	memset(ctx->stack, INVALID_VALUE, sizeof(ctx->stack)); ctx->sptr = STACKMAX - 3;
	memset(ctx->iram, 0, sizeof(ctx->iram));
	ctx->verbose = verbose;
}

static void st20_free(st20_context_t *ctx)
{
	if(ctx->flash) free(ctx->flash);
	if(ctx->ram) free(ctx->ram);
	ctx->flash = NULL;
	ctx->ram = NULL;
}

static void st20_set_call_frame(st20_context_t *ctx, uint32_t raddr, int32_t p1, int32_t p2, int32_t p3)
{
	ctx->Wptr -= 16;
	st20_wword(ctx, ctx->Wptr, raddr); // RET
	st20_wword(ctx, ctx->Wptr + 4, p1);  //Areg
	st20_wword(ctx, ctx->Wptr + 8, p1);  //Breg
	st20_wword(ctx, ctx->Wptr + 12, p1); //Creg
	st20_wword(ctx, ctx->Wptr + 16, p2);
	st20_wword(ctx, ctx->Wptr + 20, p3);
	st20_set_reg(ctx, AREG, raddr);    // RET
}

int st20_run(uint8_t* snip, uint32_t snip_len, int addr, uint8_t *data, uint16_t overcryptId)
{
	int error = 0, i, n;
	st20_context_t ctx;

	cs_log("[icg] decrypt address = 0x%X, id = %04X", addr, overcryptId);

	cs_log("[icg] CW: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X "
											,data[0], data[1], data[2] , data[3] , data[4] , data[5] , data[6] , data[7]
											,data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]);
	for(n=0;n<2;n++)
	{
		memset(&ctx, 0, sizeof(st20_context_t));
		st20_set_ram(&ctx, NULL, 0x1000);
		st20_set_flash(&ctx, snip + 0x48, (int) (snip_len - 0x48));
		st20_init(&ctx, FLASHS + addr, RAMS + 0x100, 1);
		st20_set_call_frame(&ctx, 0, RAMS, RAMS, RAMS);
		for(i = 0; i < 8; i++) st20_wbyte(&ctx, RAMS + i, data[i+n*8]);
		if ((error = st20_decode(&ctx, 800000)) < 0) break;
		cs_log("[icg] cw%d ret = %d, AREG = %X", n+1, error, st20_get_reg(&ctx, AREG));
		for(i = 0; i < 8; i++) data[i+n*8] = st20_rbyte(&ctx, RAMS + i);
		st20_free(&ctx);
	}
	
	if(error < 0)
	{
		cs_log("[icg] st20 processing failed with error %d", error);
		return 0;
	}
	
	cs_log("[icg] DW: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X "
											,data[0], data[1], data[2] , data[3] , data[4] , data[5] , data[6] , data[7]
											,data[8], data[9], data[10], data[11], data[12], data[13], data[14], data[15]);
	return 1;
}

