# Principal tier policy — phase 2

Every gRPC RPC across the platform, and the minimum `SophiePrincipal` tier its interceptor
must require once `sophie.security.enforce=true`. This is the source doc for each service's
`PrincipalTierPolicy` bean (Step 2/3) — the code should not diverge from this table without
updating it here first.

Tiers, strongest to weakest:
- **UP** `UserPrincipal` — JWT-signature-verified real user. Default for everything unless listed otherwise below.
- **AUP** `AssertedUserPrincipal` — internal secret + asserted user id. Proves "an internal service says this user", not the user's own signature.
- **SP** `ServicePrincipal` — internal secret only, no user behind the call.

Rule from the phase-2 brief: anything that grants privilege or crosses a tenant boundary must
require **UP**, never AUP — a compromised service holding the shared secret must not be able to
assert its way into a privileged action.

---

## org_service.proto (41 RPCs) — highest risk, owns all role/permission/membership state

| RPC | Tier | Why |
|---|---|---|
| ValidateSession | **SP** | Gateway-only session bootstrap; this is where identity gets minted, not consumed. Must never accept an assertion (nothing to assert yet). |
| CreateOrganization | **UP** | Creates a tenant; `created_by_user_id` must not be spoofable to attribute org creation to someone else. |
| GetOrganization | UP | Low-sensitivity read; default tier still applies (no identity field today — verify no cross-tenant leak once enforced). |
| SignUp | **SP, no user principal** | No user exists yet. Must stay reachable with internal secret only — never a bare unauthenticated call. Not "public" — the secret is what keeps it internal. |
| CreateOrgMember | **UP** | Comment: caller must be org's Org Admin. Provisions membership + role — privilege grant. |
| ListOrgMembers | UP | Org Admin only. |
| SearchOrgMembers | UP | Any member — lower sensitivity but still real-user scoped. |
| IsOrgMember | **SP** | Self-documented trusted-internal check; this RPC *is* the access-check primitive other services gate on. |
| IsOrgAdmin | **SP** | Same. |
| HasScopeAccess | **SP** | Same. |
| ListScopeMembers | **SP** | Brief's original allowlist entry (task→org). Confirmed correct — no tenant-scoping field at all, must stay internal-only. |
| IsScopeAdmin | **SP** | Trusted-internal. |
| AssignScopeRole | **SP** | Privilege **grant** with zero identity field. Must be locked to ServicePrincipal callers only — never reachable via an asserted-user context. Distinct from the public `AssignRole` below. |
| HasRoleAssignment | **SP** | Trusted-internal. |
| RoleExists | **SP** | Trusted-internal existence check. |
| BatchGetUsers | **SP** | Cross-tenant identity lookup, no org-scoping — same trust level as IsOrgMember. |
| ListMyOrganizations | UP | Caller's own org memberships. |
| UpdateOrganization | UP | Org Admin only. |
| UpdateOrganizationStatus | **UP** | ARCHIVED = effective tenant deletion. Never an assertion. |
| GetMyOrganizationBySubdomain | UP | |
| CreateRole | **UP** | Org Admin only; defines privilege. |
| UpdateRole | **UP** | Same. |
| DeleteRole | **UP** | Same, destructive. |
| ListRoles | UP | |
| AssignRole | **UP** | Public, admin-gated role assignment — the brief's canonical "never accept an assertion" example. |
| RevokeRoleAssignment | **UP** | Privilege change. |
| ListRoleAssignments | UP | |
| ListPermissions | UP | Read-only reference data; low sensitivity, default tier is enough. |
| CreateAppSection / RenameAppSection / ReorderAppSections / DeleteAppSection | UP | Admin-gated. |
| ListAppSections | UP | |
| CreateApp / UpdateApp / DeleteApp / ReorderApps | UP | Admin-gated; UpdateApp also touches visibility_subjects (access-control-adjacent). |
| ListApps | UP | |
| ToggleAppFavorite | UP | User-owned preference. |
| GetAppIconDownloadUrl | UP | |

## task_service.proto (59 RPCs)

Default **UP** for all — projects, task types, workflow, boards, labels, tasks, comments,
sprints, doc-links. Explicit exceptions:

| RPC | Tier | Why |
|---|---|---|
| ResolveTaskReferenceInternal | **SP** | Brief's original allowlist entry (integration→task). Confirmed correct — proto comment: "no requested_by, no access check... reachable only from other backend services." |
| ListVcsReferencesForTask | UP | VCS references moved here from vcs_service.proto's ListReferencesForEntity as part of the vcs-service -> integration-service split — unlike the old RPC, this one does its own project-access check (same load GetTask does), so it's genuine UP, not an assertion. |
| ProcessVcsWebhookEvent | **SP** | New with the split — integration-service calls this after verifying a GitHub/GitLab webhook signature/token and resolving the connection; no user in context, same trust tier as ResolveTaskReferenceInternal. |
| DeleteVcsReferencesForConnection | **SP** | New with the split — integration-service calls this from its DisconnectIntegration flow to clean up references that now live in a different service's DB. |
| CreateTaskType / UpdateTaskType / DeleteTaskType | UP | Org-admin-gated catalog changes. |
| CreateTask | UP | Note: optional `reporter_id` can currently be set by the caller to attribute a task to someone else — flagged for the handler-level fix in Step 3, not a tier change. |
| BatchGetTaskSummaries | UP | "No per-task filtering beyond normal authenticated caller" per comment — confirm this isn't over-broad once enforced; keep at UP, don't downgrade. |
| LinkDoc | UP | Cross-service call to Doc Service — verify the *user's* identity is forwarded (not re-asserted with elevated trust) when Task Service calls Doc Service on the user's behalf. |

## doc_service.proto (37 RPCs)

Default **UP** for all — spaces, pages, drafts, versions, locks, comments, restrictions,
task-links. Two RPCs are cross-service and need explicit identity-chain verification during Step 3
rather than a blanket AUP/SP grant:

| RPC | Tier | Why |
|---|---|---|
| AddPageRestriction / RemovePageRestriction | **UP** | Access-control change — brief's explicit "never assert" category. |
| EditComment / DeleteComment | UP | Author-only — needs the real user to enforce authorship, not an asserted id. |
| FilterAccessiblePages | UP (verify) | Called by Search Service on behalf of a user; Search must forward the *real* user identity here, not its own service identity — this gates page visibility. If Search can't forward a real UserPrincipal, this becomes the one legitimate AUP case in Doc Service, but default to requiring UP and only relax if Step 3 verification shows it's structurally impossible. |
| ListDocsLinkedToTask | UP (verify) | Same cross-service identity-chain concern, called from Task Service. |

## chat_service.proto (21 RPCs)

Identity here travels via `x-user-id` gRPC metadata (propagated from the verified principal), not
a message field — structurally different from Doc/Task/Org but the tier requirement is identical.
Default **UP** for all messaging/reactions/pins/read-state. Never-assert exceptions:

| RPC | Tier | Why |
|---|---|---|
| CreateGroupChannel | **UP** | Grants creator OWNER. |
| AddConversationMember / RemoveConversationMember | **UP** | Membership change, OWNER/ADMIN-gated. |
| TransferOwnership | **UP** | Privilege transfer — "only the current OWNER may call." Highest-risk chat RPC. |
| EditMessage | UP | Sender-only. |
| DeleteMessage | UP | Sender or role-gated. |
| UpdateChannelDescription / UpdateChannelName | UP | OWNER/ADMIN-gated. |

## search_service.proto (2 RPCs)

| RPC | Tier | Why |
|---|---|---|
| SearchMessages | UP | Live membership-filtered per comment — good, keep UP. |
| SearchPages | UP (verify) | Downstream calls Doc Service's `FilterAccessiblePages` — same identity-forwarding concern as above; confirm Search forwards the real user, doesn't assert its own identity. |

## integration_service.proto (6 RPCs) — renamed from vcs_service.proto

Connections only now (GitHub/GitLab, Google today) — VCS reference reading moved to
task_service.proto's ListVcsReferencesForTask (see above) as part of the vcs-service ->
integration-service split. GitHub/GitLab stay org-admin-gated UP calls; Google is self-service
(personal, not org-wide — see GoogleOAuthService's class doc) and requires only org membership.
`GetAccessToken` is this service's first-ever SP entry, added when calendar-service's Google sync
needed to call the Calendar API directly — defines a `PrincipalTierPolicy`
(`IntegrationPrincipalTierPolicy`) for the first time.

| RPC | Tier | Why |
|---|---|---|
| ListConnections | UP | Admin sees every connection; non-admin sees only their own self-service (Google) connections. Never returns tokens. |
| DisconnectIntegration | UP | Admin: any connection, destructive. Non-admin: only their own Google connection. |
| InitiateInstallation / InitiateGitLabOAuth | UP | Org admin only — GitHub/GitLab are org-wide. |
| ConfirmGitLabGroupSelection | **UP** | Org admin re-check + stores real OAuth tokens — high-value target, must be genuine user even though it re-checks server-side. |
| InitiateGoogleOAuth | **UP** | Self-service — requires org membership, not admin (checked via `IsOrgMember`, not `IsOrgAdmin`). Google's own OAuth consent requires the actual account holder to authenticate, so this can never be admin-initiated-on-behalf-of-another-user. |
| GetAccessToken | **SP** | No `requested_by`, no access check — internal-only, reachable only from calendar-service, which has already verified via `ListConnections` that the caller owns the `connection_id` before calling this. |

## calendar_service.proto — predates this audit doc except for one new SP entry

The other 13 RPCs on this service default to UP and were not part of the original phase-2 audit
this document captures — not reviewed here. Documenting only the one RPC added alongside
integration-service's `GetAccessToken` above, which needed a symmetric internal-only cleanup path:

| RPC | Tier | Why |
|---|---|---|
| DeleteExternalCalendarDataForConnection | **SP** | Called by integration-service's `DisconnectIntegration` flow to clean up synced Google Calendar data — same pattern as task_service.proto's `DeleteVcsReferencesForConnection`. No user in context. |

## file_service.proto (8 RPCs) — entire service is internal-only by design

Proto's own service comment: "gRPC-only, internal service-to-service — there is NO
caller-identity/permission check here... the calling service is responsible for having verified
the user may upload/attach/download before calling."

| RPC | Tier | Why |
|---|---|---|
| RequestUpload | **SP** | `uploaded_by` trusted verbatim from caller — no identity lookup of its own. |
| ConfirmUpload | **SP** | |
| GetFile | **SP** | No org/identity scoping — metadata-only, but must never be Gateway-reachable directly. |
| AttachFileReference | **SP** | Caller has already authorized the link. |
| GetDownloadUrl | **SP** | The actual content-access gate has zero checks of its own — relies entirely on Chat/Doc's per-message/per-page `GetAttachmentDownloadUrl` never being bypassed. Must never be Gateway-reachable directly. |
| ReplaceReferences | **SP** | Wholesale reference-set replace for one owner. Caller (doc-service) has already resolved page access before calling; only does a light cross-org check against `org_id` when given. |
| RevokeOwner | **SP** | Convenience for `ReplaceReferences` with an empty file set. |
| GetReferenceCount | **SP** | Debug/admin only — not on the GC sweeper's hot path (which re-checks refcount inside its own delete transaction). Must never be Gateway-reachable directly. |

## subscription_service.proto (6 RPCs, Phase 1) — entire service is internal-only by design, like File Service

Every RPC is called by another backend service (org-service's signup saga; eventually file/doc/task/
chat's own entitlement checks) — never directly by api-gateway on a user's behalf, since the Gateway
REST surface (design doc §11) isn't built yet. Blanket **SP**, same reasoning as `file_service.proto`.

| RPC | Tier | Why |
|---|---|---|
| GetEntitlements | **SP** | The access-check primitive other services gate on — same trust level as org-service's `IsOrgMember`. |
| CheckEntitlement | **SP** | Same. |
| CheckSeatAvailable | **SP** | Informational read only (real enforcement is the caller's own transactional count) — same tier regardless. |
| GetSubscription | **SP** | No Gateway-facing caller yet. Reclassify when `/api/v1/subscription` (design §11) is built — a real user would then be behind the call. |
| CreateFreeSubscription | **SP** | Called from org-service's signup saga, itself already past its own privilege checks; no user context to assert, same reasoning as org-service's `SignUp`. |
| ListPlans | **SP** | Public catalog data today; same "no Gateway caller yet" reasoning as `GetSubscription`. |

## notification_service.proto (7 RPCs)

| RPC | Tier | Why |
|---|---|---|
| CreateNotification | **SP** | Brief's original allowlist entry (chat→notification). Confirmed correct — "any backend service may create a notification for any recipient," writes into another user's feed by design. |
| ListMyNotifications / MarkNotificationRead / MarkAllRead / GetUnreadCount | UP | Caller-scoped via verified identity. |
| RegisterPushToken | UP | Upserts caller's own device token. |
| UnregisterPushToken | UP (documented risk) | Proto comment says this is explicitly *token*-scoped, not caller-scoped — anyone holding a token value can unregister it, treated as a device secret by design. Keep at UP for the *call*, but this is a pre-existing accepted-risk design choice, not something Step 3 should silently "fix" by loosening/tightening without flagging it back to you first. |

---

## Summary — ServicePrincipal allowlist (revised; supersedes the brief's list of 3)

The brief listed 3 SP-eligible RPCs from phase 1. The real, complete list is 22 (was 18 pre-split;
the vcs-service -> integration-service split removed the one AUP entry and added two genuine SP
ones; the calendar-integration work added two more — integration-service's `GetAccessToken` and
calendar-service's `DeleteExternalCalendarDataForConnection`):

- org: `ValidateSession`, `SignUp`, `IsOrgMember`, `IsOrgAdmin`, `HasScopeAccess`, `ListScopeMembers`, `IsScopeAdmin`, `AssignScopeRole`, `HasRoleAssignment`, `RoleExists`, `BatchGetUsers`
- task: `ResolveTaskReferenceInternal`, `ProcessVcsWebhookEvent`, `DeleteVcsReferencesForConnection`
- notification: `CreateNotification`
- file-service: all 5 RPCs (`RequestUpload`, `ConfirmUpload`, `GetFile`, `AttachFileReference`, `GetDownloadUrl`)
- integration: `GetAccessToken`
- calendar: `DeleteExternalCalendarDataForConnection`
- subscription-service: all 6 Phase-1 RPCs (`GetEntitlements`, `CheckEntitlement`, `CheckSeatAvailable`, `GetSubscription`, `CreateFreeSubscription`, `ListPlans`)

Everything else in the platform (~150 RPCs) requires genuine `UserPrincipal`. Nothing else is
allowlisted for a weaker tier. integration-service and calendar-service each define exactly one
`PrincipalTierPolicy` entry (`GetAccessToken` and `DeleteExternalCalendarDataForConnection`
respectively) — both previously had none.
