# -*- coding: utf-8 -*-
import os
import sys

try:
    from shutil import which
except ImportError:
    # Versions prior to Python 3.3 don't have shutil.which

    def which(cmd, mode=os.F_OK | os.X_OK, path=None):
        def _access_check(fn, mode):
            return (
                    os.path.exists(fn) and os.access(fn, mode) and not os.path.isdir(fn)
            )

        if os.path.dirname(cmd):
            if _access_check(cmd, mode):
                return cmd
            return None

        if path is None:
            path = os.environ.get("PATH", os.defpath)
        if not path:
            return None

        path = path.split(os.pathsep)

        if sys.platform == "win32":
            if os.curdir not in path:
                path.insert(0, os.curdir)

            pathext = os.environ.get("PATHEXT", "").split(os.pathsep)
            if any(cmd.lower().endswith(ext.lower()) for ext in pathext):
                files = [cmd]
            else:
                files = [cmd + ext for ext in pathext]
        else:
            files = [cmd]

        seen = set()
        for dir in path:
            normdir = os.path.normcase(dir)
            if normdir not in seen:
                seen.add(normdir)
                for thefile in files:
                    name = os.path.join(dir, thefile)
                    if _access_check(name, mode):
                        return name

        return None
