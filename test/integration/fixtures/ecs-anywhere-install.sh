#!/bin/bash
# Stub for ecs-anywhere-install-latest.sh.
#
# register_instance() downloads the real installer and then runs it with
# --region/--cluster/--activation-id/--activation-code/--docker-install-source.
# The download goes through the curl mock (which can be pointed at this file),
# and the run is a no-op here: it must (a) start with `#!/bin/bash` so
# register_instance's shebang sanity check passes, and (b) exit 0.
exit 0
