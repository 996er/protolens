"""Linux exec launcher: stop AFLNet even if its Python parent is killed."""
from __future__ import annotations

import ctypes
import os
import signal
import sys


def main() -> None:
    parent_pid = int(sys.argv[1])
    command = sys.argv[2:]
    libc = ctypes.CDLL(None, use_errno=True)
    # PR_SET_PDEATHSIG survives exec and invokes AFLNet's normal stop handler.
    # Configure it here, after Popen's exec, to avoid Python work after fork.
    if libc.prctl(1, int(signal.SIGTERM), 0, 0, 0) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    # The parent may have died before the notification was installed.
    if os.getppid() != parent_pid:
        raise SystemExit(128 + signal.SIGTERM)
    os.execvpe(command[0], command, os.environ)


if __name__ == "__main__":
    main()
