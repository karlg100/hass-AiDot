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

## Isolated local probes (2026-10-31)

The inspected hub runs firmware 1.06.11. Opening a second control session while
HA's listener was active interrupted both connections. The exact existing
single-light transport also failed in that arrangement. After temporarily
disabling just the AiDot entry through HA's supported config-entry API, the
same single-light on/off baseline succeeded with code 200 and member reports.
HA was re-enabled afterward and normal control was verified again. The tested
hub therefore needs exclusive access for a standalone probe; use HA's shared
session for any eventual integration feature.

Earlier `getDevAttrReq` probes made with a competing session are inconclusive.
They do not establish that either reads or native group writes are unsupported.

With the normal single-light baseline passing in isolation, the bounded
on/off-only write experiments produced:

| Experimental request | Result |
| --- | --- |
| Group cloud ID in the ordinary `setDevAttrReq` device fields | Rejected, code -2 |
| Decimal mesh group address in those fields | Rejected, code -2 |
| Hub as destination plus group ID/address payload fields | Rejected, code -10 |
| Known member as destination plus those group payload fields | Code 200; only that member reported a change |
| Guessed `setGroupAttrReq` / `setGroupDevAttrReq` method names, including a `group` service variant | No correlated acknowledgement within the probe timeout |

These are unsuccessful encoding hypotheses, not a verified list of supported
protocol methods. No unverified method has been added to the integration.
Normal individual off commands for all 14 members were acknowledged during
cleanup. The entry returned to loaded/enabled, with a connected hub and no
connection error; HA on/off control was checked after restoration.

## Synchronized phone-app capture

A second test used a ready/recording/done handshake. The user operated the app
group on, waited five seconds, then off while other controllers were paused.
The capture ran for 57.2 seconds, with all 14 entities initially reporting off
and the HA hub connection healthy.

The trace contained two `pingreq`/`pingresp` pairs, no light commands and no
device attribute reports. The diagnostic device-update counters did not
increase for any of the 14 lights. Thus this capture did not expose the app's
group operation. It cannot distinguish direct phone Bluetooth, phone LAN
traffic outside the HA host's visibility, or a cloud path. Repeating the same
capture point will not by itself reveal a command encoding.

The user then confirmed physical group on/off operation with Bluetooth off in
iPhone Settings, followed by a second successful test with both Bluetooth and
Wi-Fi off and cellular data on. This establishes a cloud-to-hub control path;
direct phone Bluetooth and phone LAN access are not required for that path.
It does not establish whether the cloud sends one mesh group request or fans
out individual member commands, nor does it establish a latency improvement.

## Cloud observation

AiDot's [official web client](https://app.aidot.com/SignIn), examined on
2026-10-31, obtains a per-session MQTT configuration from
`GET /v29/commons/mqttConfig?source=WebPC&sessionId=...`. Its public bundle
constructs a TLS WebSocket connection to the returned host at `/mqtt` and
contains the ordinary individual `setDevAttrReq` builder. No mesh group
request builder was found in that bundle; this is not evidence that the
phone app lacks one.

A bounded read-only observer authenticated successfully using the existing
HA account token and a separate WebPC session nonce. TLS certificate
validation remained enabled. The broker accepted the account's client
notification channel and the owned hub's broadcast channel, but rejected
subscriptions to the server-request, hub-client and user-broadcast channels.
Those rejected subscriptions were not retried or bypassed. No cloud device
command was published, and no MQTT password was saved.

During controlled HA single-light on/off tests, the hub's broadcast channel
yielded acknowledgements with code 200, the member's `devId` and `attr.OnOff`
values 1 and 0. These establish acknowledgement visibility, not independent
physical feedback or access to the phone's outgoing request. Spotlight 14 was
returned to off. A bounded recorder is prepared for an app group test at this
different observation point. The actual group request or app implementation
is still required before adding a group write.

Do not present a successful hub acknowledgement as proof that all members
received a command. Verification needs a single outgoing group request plus
independent member reports, explicit read-back or physical observation.
An unacknowledged mesh broadcast may not generate individual status reports;
the lack of passive reports alone does not prove delivery failed.

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
