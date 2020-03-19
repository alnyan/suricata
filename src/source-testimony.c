#include "suricata-common.h"
#include "suricata.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "source-testimony.h"

#ifdef HAVE_TESTIMONY
#include <testimony.h>

typedef struct TestimonyThreadVars_ {
    ThreadVars *tv;
    TmSlot *slot;
    testimony_iter iter;
    testimony t;
    int running;
} TestimonyThreadVars;

static TmEcode ReceiveTestimonyLoop(ThreadVars *tv, void *data, void *slot);
static TmEcode ReceiveTestimonyThreadInit(ThreadVars *tv, const void *initdata, void **data);
static TmEcode ReceiveTestimonyThreadDeinit(ThreadVars *tv, void *data);
static TmEcode ReceiveTestimonyBreakLoop(ThreadVars *tv, void *data);
static void ReceiveTestimonyThreadExitStats(ThreadVars *tv, void *data);

static TmEcode DecodeTestimonyThreadInit(ThreadVars *, const void *, void **);
static TmEcode DecodeTestimonyThreadDeinit(ThreadVars *tv, void *data);
static TmEcode DecodeTestimony(ThreadVars *, Packet *, void *);

void TmModuleReceiveTestimonyRegister (void)
{
    tmm_modules[TMM_RECEIVETESTIMONY].name = "ReceiveTestimony";
    tmm_modules[TMM_RECEIVETESTIMONY].ThreadInit = ReceiveTestimonyThreadInit;
    tmm_modules[TMM_RECEIVETESTIMONY].PktAcqLoop = ReceiveTestimonyLoop;
    tmm_modules[TMM_RECEIVETESTIMONY].PktAcqBreakLoop = ReceiveTestimonyBreakLoop;
    tmm_modules[TMM_RECEIVETESTIMONY].ThreadExitPrintStats = ReceiveTestimonyThreadExitStats;
    tmm_modules[TMM_RECEIVETESTIMONY].ThreadDeinit = ReceiveTestimonyThreadDeinit;
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

static void AddTestimonyPacket(TestimonyThreadVars *ttv, ThreadVars *tv, const struct tpacket3_hdr *tp)
{
    const uint8_t *packet_data;
    size_t packet_length;

    SCEnter();

    packet_data = testimony_packet_data(tp);
    if (unlikely(packet_data == NULL)) {
        SCReturn;
    }
    packet_length = tp->tp_snaplen;

    Packet *p = PacketGetFromQueueOrAlloc();
    if (unlikely(p == NULL)) {
        SCReturn;
    }

    PKT_SET_SRC(p, PKT_SRC_WIRE);
    p->ts.tv_sec = tp->tp_sec;
    p->ts.tv_usec = tp->tp_nsec / 1000;
    p->datalink = LINKTYPE_ETHERNET;

    if (unlikely(PacketCopyData(p, packet_data, packet_length))) {
        TmqhOutputPacketpool(tv, p);
        SCReturn;
    }

    if (TmThreadsSlotProcessPkt(tv, ttv->slot, p) != TM_ECODE_OK) {
        ttv->running = 0;
    }
}

static TmEcode ReceiveTestimonyLoop(ThreadVars *tv, void *data, void *slot)
{
    int res;
    const struct tpacket_block_desc* block;
    const struct tpacket3_hdr* packet;

    SCEnter();
    TestimonyThreadVars *ttv = (TestimonyThreadVars *) data;

    TmSlot *s = (TmSlot *)slot;
    ttv->slot = s->slot_next;

    testimony_iter_init(&ttv->iter);

    while (ttv->running) {
        res = testimony_get_block(ttv->t, 100, &block);
        if (res == 0 && !block) {
            // Timed out
            continue;
        }
        if (res < 0) {
            SCLogError(SC_ERR_TESTIMONY_GET_BLOCK, "testimony_get_block(): %s, %s",
                    testimony_error(ttv->t),
                    strerror(-res));
            SCReturnInt(TM_ECODE_FAILED);
        }

        testimony_iter_reset(ttv->iter, block);
        while ((packet = testimony_iter_next(ttv->iter)) != NULL) {
            AddTestimonyPacket(ttv, tv, packet);
        }

        res = testimony_return_block(ttv->t, block);
        if (res < 0) {
            SCLogError(SC_ERR_TESTIMONY_GET_BLOCK, "testimony_return_block(): %s, %s",
                    testimony_error(ttv->t),
                    strerror(-res));
            SCReturnInt(TM_ECODE_FAILED);
        }
    }

    SCReturnInt(TM_ECODE_OK);
}

static TmEcode ReceiveTestimonyThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    const char *socket_path;
    int res;

    SCEnter();

    if (ConfGet("testimony.socket-path", &socket_path) != 1) {
        SCLogError(SC_ERR_TESTIMONY_CREATE, "No testimony socket path is set\n");
        SCReturnInt(TM_ECODE_FAILED);
    }

    TestimonyThreadVars *ttv = SCCalloc(1, sizeof(TestimonyThreadVars));
    if (unlikely(ttv == NULL)) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    SCLogInfo("Socket path: %s", socket_path);

    res = testimony_connect(&ttv->t, socket_path);
    if (res < 0) {
        SCLogError(SC_ERR_TESTIMONY_CREATE, "testimony_connect(): %s", strerror(-res));
        //perror("testimony_connect()");
        SCReturnInt(TM_ECODE_FAILED);
    }

    res = testimony_init(ttv->t);
    if (res < 0) {
        SCLogError(SC_ERR_TESTIMONY_CREATE, "testimony_init(): %s, %s",
                testimony_error(ttv->t),
                strerror(-res));
        testimony_close(ttv->t);
        SCReturnInt(TM_ECODE_FAILED);
    }

    ttv->tv = tv;
    ttv->running = 1;

    *data = ttv;
    SCReturnInt(TM_ECODE_OK);
}

static TmEcode ReceiveTestimonyThreadDeinit(ThreadVars *tv, void *data) {
    SCEnter();

    TestimonyThreadVars *ttv = (TestimonyThreadVars *) data;
    testimony_close(ttv->t);

    SCReturnInt(TM_ECODE_OK);
}

static TmEcode ReceiveTestimonyBreakLoop(ThreadVars *tv, void *data)
{
    SCEnter();
    TestimonyThreadVars *ttv = (TestimonyThreadVars *)data;
    ttv->running = 0;
    SCReturnInt(TM_ECODE_OK);
}

static void ReceiveTestimonyThreadExitStats(ThreadVars *tv, void *data)
{
    SCEnter();
    SCReturn;
}

static TmEcode DecodeTestimony(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    // All packets are assumed to be ethernet when using testimony
    DecodeEthernet(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p));

    SCReturnInt(TM_ECODE_OK);
}

static TmEcode DecodeTestimonyThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    SCEnter();

    DecodeThreadVars *dtv = DecodeThreadVarsAlloc(tv);
    if (unlikely(dtv == NULL)) {
        SCReturnInt(TM_ECODE_FAILED);
    }

    DecodeRegisterPerfCounters(dtv, tv);

    *data = (void *)dtv;

    SCReturnInt(TM_ECODE_OK);
}

static TmEcode DecodeTestimonyThreadDeinit(ThreadVars *tv, void *data)
{
    SCEnter();
    SCReturnInt(TM_ECODE_OK);
}

#endif
