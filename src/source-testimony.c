#include "suricata-common.h"
#include "suricata.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "source-testimony.h"

#include <stdio.h>

typedef struct TestimonyThreadVars_ {
    ThreadVars *tv;
    int running;
} TestimonyThreadVars;

static TmEcode ReceiveTestimonyLoop(ThreadVars *tv, void *data, void *slot);
static TmEcode ReceiveTestimonyThreadInit(ThreadVars *tv, const void *initdata, void **data);
static TmEcode ReceiveTestimonyBreakLoop(ThreadVars *tv, void *data);
static void ReceiveTestimonyThreadExitStats(ThreadVars *tv, void *data);

static TmEcode DecodeTestimonyThreadInit(ThreadVars *, const void *, void **);
static TmEcode DecodeTestimonyThreadDeinit(ThreadVars *tv, void *data);
static TmEcode DecodeTestimony(ThreadVars *, Packet *, void *);

void TmModuleReceiveTestimonyRegister (void)
{
    printf("%s\n", __func__);
    tmm_modules[TMM_RECEIVETESTIMONY].name = "ReceiveTestimony";
    tmm_modules[TMM_RECEIVETESTIMONY].ThreadInit = ReceiveTestimonyThreadInit;
    tmm_modules[TMM_RECEIVETESTIMONY].PktAcqLoop = ReceiveTestimonyLoop;
    tmm_modules[TMM_RECEIVETESTIMONY].PktAcqBreakLoop = ReceiveTestimonyBreakLoop;
    tmm_modules[TMM_RECEIVETESTIMONY].ThreadExitPrintStats = ReceiveTestimonyThreadExitStats;
    tmm_modules[TMM_RECEIVETESTIMONY].cap_flags = 0; //SC_CAP_NET_RAW;
    tmm_modules[TMM_RECEIVETESTIMONY].flags = TM_FLAG_RECEIVE_TM;
}

void TmModuleDecodeTestimonyRegister (void)
{
    tmm_modules[TMM_DECODETESTIMONY].name = "DecodeTestimony";
    tmm_modules[TMM_DECODETESTIMONY].ThreadInit = DecodeTestimonyThreadInit;
    tmm_modules[TMM_DECODETESTIMONY].Func = DecodeTestimony;
    tmm_modules[TMM_DECODETESTIMONY].ThreadDeinit = DecodeTestimonyThreadDeinit;
    tmm_modules[TMM_DECODETESTIMONY].flags = TM_FLAG_DECODE_TM;
}

static TmEcode ReceiveTestimonyLoop(ThreadVars *tv, void *data, void *slot)
{
    SCEnter();
    printf("%s\n", __func__);
    TestimonyThreadVars *ttv = (TestimonyThreadVars *) data;

    while (ttv->running) {
        usleep(100000);
    }

    SCReturnInt(TM_ECODE_OK);
}

static TmEcode ReceiveTestimonyThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCEnter();
    printf("%s\n", __func__);
    TestimonyThreadVars *ttv = SCCalloc(1, sizeof(TestimonyThreadVars));
    if (unlikely(ttv == NULL)) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    ttv->tv = tv;
    ttv->running = 1;

    *data = ttv;
    SCReturnInt(TM_ECODE_OK);
}

static TmEcode ReceiveTestimonyBreakLoop(ThreadVars *tv, void *data)
{
    SCEnter();
    printf("%s\n", __func__);
    TestimonyThreadVars *ttv = (TestimonyThreadVars *)data;
    ttv->running = 0;
    //if (ptv->pcap_handle == NULL) {
    //    SCReturnInt(TM_ECODE_FAILED);
    //}
    //pcap_breakloop(ptv->pcap_handle);
    SCReturnInt(TM_ECODE_OK);
}

static void ReceiveTestimonyThreadExitStats(ThreadVars *tv, void *data)
{
    SCEnter();
}

static TmEcode DecodeTestimony(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();
    SCReturnInt(TM_ECODE_OK);
}

static TmEcode DecodeTestimonyThreadInit(ThreadVars *tv, const void *initdata, void **data)
{

    SCEnter();
    SCReturnInt(TM_ECODE_OK);
}

static TmEcode DecodeTestimonyThreadDeinit(ThreadVars *tv, void *data)
{
    SCReturnInt(TM_ECODE_OK);
}
