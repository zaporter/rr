#include "RecordingInterface.h"

#include <linux/capability.h>
#include <spawn.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <iostream>
#include <sysexits.h>
#include <time.h>

#include "preload/preload_interface.h"

#include "Flags.h"
#include "StringVectorToCharArray.h"
#include "WaitStatus.h"
#include "git_revision.h"
#include "kernel_metadata.h"
#include "log.h"

using namespace std;

namespace rr {


} // namespace rr
