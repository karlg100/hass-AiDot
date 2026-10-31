# Native mesh group command investigation

Branch: `codex/mesh-group-commands`, based on consolidated fork main
`5ba7abc04c6d72d8801e452a369471b8bb7894a9`.
The existing contribution remains separate in upstream PR #42.

## Confirmed

An AiDot account's existing groups can be read with `GET /groups?houseId=...`,
alongside the `/houses` and `/devices?houseId=...` endpoints already used by
python-aidot. A normal outdoor group exposes:

- `id`: cloud group identifier; this is distinct from a mesh destination.
- `deviceIds`: explicit cloud device membership.
- `bleMeshGroupType`: `normal` on the inspected group.
- `bleMeshGroupAddress`: a decimal string in the dynamic mesh group range.
- `bleMeshLocalGroupDevices`: additional local group metadata; its meaning has
  not been established. Do not treat its entries as cloud device identifiers.

The inspected installation has a normal outdoor group containing all 14 SL5C
lights, with a dynamic mesh group address. All members use the same hub.
No group membership, pairing, firmware or Home Assistant integration files
were changed during discovery.

Bluetooth SIG defines dynamic group destinations in `0xC000`–`0xFEFF` and
describes group publication/subscription in the
[Mesh Protocol](https://www.bluetooth.com/wp-content/uploads/Files/Specification/HTML/MshPRT_v1.1/out/en/index-en.html).
An address in this range is evidence for a possible multicast destination;
it does not establish AiDot's TCP command encoding or successful delivery.

The current integration and python-aidot 0.3.58 only expose the per-device
`setDevAttrReq` path. A normal HA light group therefore still sends one command
per member. Prior live tests measured approximately five individual commands
per second, with a 14-light operation taking about 2.7 seconds.

## Read-only discovery tool

Run `python tools/mesh_groups.py --config-dir /config` in an environment with
the integration's python-aidot dependency and read access to HA's config.
Use `--entry-id` if the installation has more than one AiDot entry.

The tool reads existing account data, retrieves owned-home groups and devices,
then reports anonymous group/hub identifiers, address and member count. It
rejects unknown members, mixed hubs, non-BLE members and non-dynamic addresses.
It sends no device command and never edits group membership. Raw account/API
responses and device names are not printed or written to an output file.
`localCommandVerified` remains false until there is independent wire evidence.
The tool was also run successfully with the installed python-aidot 0.3.58 API
base (v35), finding the same 14-member group. All 86 automated tests pass,
including address classification, exact membership, shared-hub eligibility and
output redaction checks added for this tool.

## Unresolved protocol boundary

Sending `getDevAttrReq` through a separate experimental hub connection caused
that connection to close, including for a known individual light. These read
probes do not determine whether a native group write is supported.

The next reference is an app group off/on/steady-colour operation while other
controllers are paused. An HA-host packet capture can observe HA's own hub
connection and broadcast traffic; it cannot be assumed to see a phone's
unicast traffic on a switched network, or phone-to-light Bluetooth traffic.
Matching telemetry alone does not reveal the app's outgoing command format.

Do not present a successful hub acknowledgement as proof that all members
received a command. Verification must correlate a single outgoing group
request with reports from multiple member lights and physical observation.

## Implementation once the command is verified

1. Discover existing eligible AiDot groups and resolve every member to a hub.
2. Add one explicit group request to the existing shared `_HubSession` reader
   and acknowledgement dispatcher. Keep it ordered against member commands;
   independent group and per-light locks must not permit conflicting writes.
3. Expose the app group as its own HA light, supporting only attributes proven
   to work. A caller selecting ordinary individual entities keeps the existing
   semantics; do not silently broadcast to unselected group members.
4. Keep device telemetry authoritative. Track hub acceptance separately from
   member report freshness. Avoid inventing individual confirmations after a
   multicast acknowledgement.
5. Test mixed firmware, offline/sleeping members, rejected acknowledgements,
   reconnects and overlapping group/individual commands; compare a 14-light
   group action against the existing approximately 2.7-second baseline.

No native group write or all-nodes broadcast is enabled by this branch yet.
