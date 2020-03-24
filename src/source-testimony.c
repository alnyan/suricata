/* Copyright (C) 2011-2018 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 *  \defgroup testimony Testimony running mode
 *
 *  @{
 */

/**
 * \file
 *
 * \author Mark Poliakov <alnyan@protonmail.com>
 *
 * Google's Testimony Unix socket acquisition support
 *
 */

#include "suricata-common.h"
#include "suricata.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "source-testimony.h"

#ifdef HAVE_TESTIMONY
#include <testimony.h>

/**
 * \brief Structure to hold thread specific variables.
 */
typedef struct TestimonyThreadVars_ {
    ThreadVars *tv;
    TmSlot *slot;
    testimony t;
    int running;
} TestimonyThreadVars;

static TmEcode ReceiveTestimonyLoop(ThreadVars *tv, void *data, void *slot);
static TmEcode ReceiveTestimonyThreadInit(ThreadVars *tv, const void *initdata, void **data);
static TmEcode ReceiveTestimonyThreadDeinit(ThreadVars *tv, void *data);
static TmEcode ReceiveTestimonyBreakLoop(ThreadVars *tv, void *data);

static TmEcode DecodeTestimonyThreadInit(ThreadVars *, const void *, void **);
static TmEcode DecodeTestimonyThreadDeinit(ThreadVars *tv, void *data);
static TmEcode DecodeTestimony(ThreadVars *, Packet *, void *);

/**
 * \brief Registration function for ReceiveTestimony.
 */
void TmModuleReceiveTestimonyRegister (void)
{
    tmm_modules[TMM_RECEIVETESTIMONY].name = "ReceiveTestimony";
    tmm_modules[TMM_RECEIVETESTIMONY].ThreadInit = ReceiveTestimonyThreadInit;
    tmm_modules[TMM_RECEIVETESTIMONY].PktAcqLoop = ReceiveTestimonyLoop;
    tmm_modules[TMM_RECEIVETESTIMONY].PktAcqBreakLoop = ReceiveTestimonyBreakLoop;
    tmm_modules[TMM_RECEIVETESTIMONY].ThreadDeinit = ReceiveTestimonyThreadDeinit;
    tmm_modules[TMM_RECEIVETESTIMONY].ThreadExitPrintStats = NULL;
    tmm_modules[TMM_RECEIVETESTIMONY].flags = TM_FLAG_RECEIVE_TM;
}

/**
 * \brief Registration function for DecodeTestimony.
 */
void TmModuleDecodeTestimonyRegister (void)
{
    tmm_modules[TMM_DECODETESTIMONY].name = "DecodeTestimony";
    tmm_modules[TMM_DECODETESTIMONY].ThreadInit = DecodeTestimonyThreadInit;
    tmm_modules[TMM_DECODETESTIMONY].Func = DecodeTestimony;
    tmm_modules[TMM_DECODETESTIMONY].ThreadDeinit = DecodeTestimonyThreadDeinit;
    tmm_modules[TMM_DECODETESTIMONY].flags = TM_FLAG_DECODE_TM;
}

/**
 * \brief Add packet received via Testimony to decoding queue.
 */
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

    SCReturn;
}

/**
 *  \brief Main Testimony reading loop function.
 */
static TmEcode ReceiveTestimonyLoop(ThreadVars *tv, void *data, void *slot)
{
    int res;
    const struct tpacket_block_desc *block;
    const struct tpacket3_hdr *packet;
    testimony_iter iter;

    SCEnter();
    TestimonyThreadVars *ttv = (TestimonyThreadVars *) data;

    TmSlot *s = (TmSlot *)slot;
    ttv->slot = s->slot_next;

    testimony_iter_init(&iter);

    while (ttv->running) {
        PacketPoolWait();

        res = testimony_get_block(ttv->t, 100, &block);
        if (res == 0 && !block) {
            // Timed out
            StatsSyncCountersIfSignalled(tv);
            continue;
        }
        if (res < 0) {
            SCLogError(SC_ERR_TESTIMONY_GET_BLOCK, "testimony_get_block(): %s, %s",
                    testimony_error(ttv->t),
                    strerror(-res));
            StatsSyncCountersIfSignalled(tv);
            SCReturnInt(TM_ECODE_FAILED);
        }

        testimony_iter_reset(iter, block);
        while ((packet = testimony_iter_next(iter)) != NULL) {
            AddTestimonyPacket(ttv, tv, packet);
        }

        res = testimony_return_block(ttv->t, block);
        if (res < 0) {
            SCLogError(SC_ERR_TESTIMONY_GET_BLOCK, "testimony_return_block(): %s, %s",
                    testimony_error(ttv->t),
                    strerror(-res));
            StatsSyncCountersIfSignalled(tv);
            SCReturnInt(TM_ECODE_FAILED);
        }
    }

    StatsSyncCountersIfSignalled(tv);
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Init function for ReceiveTestimony
 *
 * \param tv pointer to ThreadVars
 * \param initdata ignored
 * \param data pointer gets populated with TestimonyThreadVars
 */
static TmEcode ReceiveTestimonyThreadInit(ThreadVars *tv, const void *initdata, void **data)
{
    int res;
    const char *socket_path;

    SCEnter();

    if (ConfGet("testimony.socket-path", &socket_path) != 1) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "No testimony socket path is set");
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

/**
 * \brief DeInit function closes Testimony Unix socket at exit.
 * \param tv pointer to ThreadVars
 * \param data pointer that gets cast into TestimonyThreadVars for ttv
 */
static TmEcode ReceiveTestimonyThreadDeinit(ThreadVars *tv, void *data)
{
    SCEnter();

    TestimonyThreadVars *ttv = (TestimonyThreadVars *) data;
    testimony_close(ttv->t);

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Testimony Break Loop function.
 */
static TmEcode ReceiveTestimonyBreakLoop(ThreadVars *tv, void *data)
{
    SCEnter();
    TestimonyThreadVars *ttv = (TestimonyThreadVars *)data;
    ttv->running = 0;
    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief This function passes off to link type decoders.
 *
 * DecodeTestimony decodes tpacket_v3 and passes
 * them off to the proper link type decoder.
 *
 * \param t pointer to ThreadVars
 * \param p pointer to the current packet
 * \param data ignored
 */
static TmEcode DecodeTestimony(ThreadVars *tv, Packet *p, void *data)
{
    SCEnter();
    DecodeThreadVars *dtv = (DecodeThreadVars *)data;

    printf("DECODE!\n");
    DecodeUpdatePacketCounters(tv, dtv, p);

    // All packets are assumed to be ethernet when using testimony
    DecodeEthernet(tv, dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p));

    PacketDecodeFinalize(tv, dtv, p);

    SCReturnInt(TM_ECODE_OK);
}

/**
 * \brief Init function for DecodeTestimony
 *
 * \param tv pointer to ThreadVars
 * \param initdata ignored
 * \param data pointer gets populated with DecodeThreadVars
 */
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
    if (data != NULL)
        DecodeThreadVarsFree(tv, data);
    SCReturnInt(TM_ECODE_OK);
}

#endif /* HAVE_TESTIMONY */
/* eof */
/**
 * @}
 */
