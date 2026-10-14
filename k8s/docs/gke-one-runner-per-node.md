# GKE: one runner per node

The layout tested on a zonal GKE Standard cluster: every runner gets a whole
node, nodes come and go with runners. Notes on how it behaves and the settings
we'd use.

## Setup

| Piece | Setting | Why |
|---|---|---|
| Node pool | `e2-custom-8-16384` (8 vCPU / 16 GB), autoscaling 1–4, on-demand | A default workflow needs 1 vCPU : 1.5 GiB; `e2-standard-8` (1 : 4) left over half its memory unused |
| Runner size | `runner.size=custom`, requests 6500m / 11Gi, limits 7 / 11Gi | What's left of ~7.9 CPU / ~13 GiB allocatable after GKE's DaemonSets (~0.5 CPU / 1 GiB) and the system pods on the first node. SG sees 7 CPU / ~10.7 GiB = 7 default workflows |
| Memory | request = limit | Memory can't be reclaimed; never overcommit it |
| One per node | required pod anti-affinity on `kubernetes.io/hostname` (runner labels) | Large requests already fit only one; the anti-affinity makes it explicit |
| Scaler | `scaler.max` = node pool `max_nodes` | One runner per node |
| Nudge | `scaler.nudge.enabled=true` (default) | GKE's cluster autoscaler never adds a node for a pod with a persistent disk (see [open-items.md](open-items.md)); the scaler's placeholder gets the node |

## How runners move

| Event | What happens | Time |
|---|---|---|
| Scale out, new runner | Pod Pending → autoscaler refuses (`NotTriggerScaleUp`) → nudge placeholder → node added → runner scheduled, registers | node boot (~45 s) + nudge (~15 s) + registration (~20 s) + image pulls |
| Park (idle `scaler.idleSeconds`) | Runner drains and its pod goes; volumes and SG registration stay; the empty node is removed by the autoscaler about 10 min later | 14 s park |
| Wake within ~10 min | The empty node is still there: the runner lands on it | ~8 s, as before |
| Wake after the node is gone | Nudge → new node → disk attaches → runner reconnects with its identity and image cache | ~70 s to scheduled (measured), plus reconnect |
| Reap (parked ≥ `scaler.parkTTL`) | Reap Job (no CPU/memory requests) mounts the state disk on any remaining node, deregisters, both disks deleted; no new node needed | seconds |

A parked runner costs disk only: ~21 Gi `pd-balanced` (estimate: about
$2–3/month) plus a slot in the runner group's `MaxNumberOfRunners`. Parking
pays for the image cache and avoids SSM/ECS registration churn; the node boot
is the same either way.

## Suggested settings

1. **Keep `scaler.parkTTL` at 12 h.** Image caches stay warm through a working
   day; parked runners are reaped overnight. Go to 2–4 h only if parked
   runners crowd the SG UI or `MaxNumberOfRunners`.
2. **Keep `scaler.idleSeconds` at 60.** Parking fast is cheap: the node lingers
   ~10 min (the autoscaler's scale-down delay), so a runner woken in that
   window is back in seconds.
3. **Stay on GKE's default autoscaling profile, not `optimize-utilization`.**
   With one runner per node it would only remove empty nodes sooner, losing
   that warm window for little saving (an empty node for ~10 min costs cents).
4. **Set the runner group's `MaxNumberOfRunners` in SG** to cover awake *and*
   parked runners, at least `scaler.max`; otherwise the scaler can't register
   new runners while old ones are parked.
5. **Optional: `scaler.headroomPct`** keeps a spare awake runner, here a spare
   node: no wait for the first queued workflow of a burst, at the price of one
   idle node.
6. **`scaler.nudge.cooldownSeconds` (180)** must stay above a node's boot time,
   or a second node is requested while the first boots.

## Still to verify

- Waking after a long park (hours, overnight): SSM and the ECS agent
  reconnecting after a long disconnect ([testing.md](testing.md), plan 3).
  Matters more here, since parked runners routinely sit for hours.
- The nudge releasing its placeholder at `TriggeredScaleUp` (chart 0.7.0) on
  GKE; the earlier release-when-running version is verified.
- Actual workflow usage vs the 1 vCPU / 1.5 GiB SG reserves: if far lower, the
  runner could advertise more CPU than its limit (CPU only, never memory) to
  fit more workflows per node.
