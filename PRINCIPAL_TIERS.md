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

## task_service.proto (56 RPCs)

Default **UP** for all — projects, task types, workflow, boards, labels, tasks, comments,
sprints, doc-links. Explicit exceptions:

| RPC | Tier | Why |
|---|---|---|
| ResolveTaskReferenceInternal | **SP** | Brief's original allowlist entry (vcs→task). Confirmed correct — proto comment: "no requested_by, no access check... reachable only from other backend services." |
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

## vcs_service.proto (6 RPCs)

| RPC | Tier | Why |
|---|---|---|
| ListVcsConnections | UP | Org admin only, never returns tokens. |
| DisconnectVcs | UP | Org admin only, destructive. |
| ListReferencesForEntity | **AUP/SP** | Proto comment: caller (Task Service) is trusted to have already validated access; `requested_by` is carried but never checked. This is the one RPC in the codebase that already, explicitly, treats an assertion as sufficient — keep it that way but make it a deliberate `PrincipalTierPolicy` entry rather than an accident of missing enforcement. |
| InitiateInstallation / InitiateGitLabOAuth | UP | Org admin only. |
| ConfirmGitLabGroupSelection | **UP** | Org admin re-check + stores real OAuth tokens — high-value target, must be genuine user even though it re-checks server-side. |

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

## notification_service.proto (7 RPCs)

| RPC | Tier | Why |
|---|---|---|
| CreateNotification | **SP** | Brief's original allowlist entry (chat→notification). Confirmed correct — "any backend service may create a notification for any recipient," writes into another user's feed by design. |
| ListMyNotifications / MarkNotificationRead / MarkAllRead / GetUnreadCount | UP | Caller-scoped via verified identity. |
| RegisterPushToken | UP | Upserts caller's own device token. |
| UnregisterPushToken | UP (documented risk) | Proto comment says this is explicitly *token*-scoped, not caller-scoped — anyone holding a token value can unregister it, treated as a device secret by design. Keep at UP for the *call*, but this is a pre-existing accepted-risk design choice, not something Step 3 should silently "fix" by loosening/tightening without flagging it back to you first. |

---

## Summary — ServicePrincipal allowlist (revised; supersedes the brief's list of 3)

The brief listed 3 SP-eligible RPCs from phase 1. The real, complete list is 18:

- org: `ValidateSession`, `SignUp`, `IsOrgMember`, `IsOrgAdmin`, `HasScopeAccess`, `ListScopeMembers`, `IsScopeAdmin`, `AssignScopeRole`, `HasRoleAssignment`, `RoleExists`, `BatchGetUsers`
- task: `ResolveTaskReferenceInternal`
- notification: `CreateNotification`
- vcs: `ListReferencesForEntity` (AUP, not SP — carries an unused identity field)
- file-service: all 5 RPCs (`RequestUpload`, `ConfirmUpload`, `GetFile`, `AttachFileReference`, `GetDownloadUrl`)

Everything else in the platform (~150 RPCs) requires genuine `UserPrincipal`. Nothing else is
allowlisted for a weaker tier.
