/* Copyright (C) 2007-2012 Open Information Security Foundation
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

#include "suricata-common.h"
#include "tm-threads.h"
#include "runmodes.h"
#include "runmode-testimony.h"
#include "output.h"

#include "util-runmodes.h"

void RunModeIdsTestimonyRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_TESTIMONY, "single",
                              "Single threaded testimony mode",
                              RunModeIdsTestimonySingle);
}

static void *ParseTestimonyConfig(const char *iface)
{
    return NULL;
}

static int TestimonyGetThreadsCount(void *conf)
{
    return 1;
}

/**
 * \brief Single thread version of the Testimony live processing.
 */
int RunModeIdsTestimonySingle(void)
{
    int ret;

    SCEnter();

    RunModeInitialize();
    TimeModeSetLive();

    ret = RunModeSetLiveCaptureSingle(ParseTestimonyConfig,
                                      TestimonyGetThreadsCount,
                                      "ReceiveTestimony",
                                      "DecodeTestimony",
                                      thread_name_single,
                                      "testimony");
    if (ret != 0) {
        SCLogError(SC_ERR_RUNMODE, "Runmode start failed");
        exit(EXIT_FAILURE);
    }

    SCLogInfo("RunModeIdsTestimonySingle initialised");

    SCReturnInt(0);
}
