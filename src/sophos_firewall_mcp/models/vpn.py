"""Pydantic models for the read-only Sophos VPN domains.

Two read-only families live here:

* **IPsec VPN** (11 operations): profiles, failover groups, policy-based and route-based
  IPv4 site-to-site connections, live site-to-site connections, and remote-access settings;
* **SSL VPN** (9 operations): remote-access policies, clientless policies, bookmark groups,
  bookmarks, and global settings.

VPN is read-only in v1: no request model here describes a mutation, and the tools register
no write. Response models use the API's wire names (camelCase) so every projection is
auditable against ``firewall_config_openapi.yaml``; ``extra="ignore"`` keeps a server-side
addition from breaking a read. Nothing in this module performs I/O.

Path identifiers use the shared :data:`~sophos_firewall_mcp.models.common.ObjectNameOrId`
primitive, so the name-or-id rule is defined exactly once.

Configured state and live state are kept apart on purpose: ``IpsecConnection`` and
``IpsecRouteBasedConnection`` are configuration, ``IpsecLiveConnection`` is the live
security-association view. Neither is derived from the other.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Literal, Self

from pydantic import AliasChoices, BaseModel, ConfigDict, Field, field_serializer, model_validator

from .common import ObjectNameOrId, ObjectRef
from .objects import serialize_epoch_sentinel

__all__ = [
    "BookmarkProtocol",
    "FailoverGroupListInput",
    "IpsecConnection",
    "IpsecDeadPeerDetection",
    "IpsecFailoverGroup",
    "IpsecGatewaySettings",
    "IpsecLeaseConfigurationIpv4",
    "IpsecLiveConnection",
    "IpsecNetworkSelector",
    "IpsecPeerId",
    "IpsecPhase1",
    "IpsecPhase1Algorithm",
    "IpsecPhase2",
    "IpsecPhase2Algorithm",
    "IpsecProfile",
    "IpsecProtectedNetworks",
    "IpsecRemoteAccessSettings",
    "IpsecRemoteGateway",
    "IpsecRouteBasedConnection",
    "IpsecSecurityAssociation",
    "IpsecTrafficSelector",
    "IpsecUsersOrGroups",
    "IkeSecurityAssociation",
    "LivenessCheck",
    "RemoteAccessProtectedNetworks",
    "SophosConnectAutoConnect",
    "SophosConnectClientSettings",
    "SslVpnBookmark",
    "SslVpnBookmarkGroup",
    "SslVpnClientlessPolicy",
    "SslVpnGlobalSettings",
    "SslVpnLease",
    "SslVpnOverrideHost",
    "SslVpnPermittedNetworksIpv4",
    "SslVpnPermittedNetworksIpv6",
    "SslVpnPolicyMembers",
    "SslVpnRemoteAccessPolicy",
    "SslVpnUsersOrGroups",
    "VpnBookmarkGroupRefInput",
    "VpnBookmarkRefInput",
    "VpnClientlessPolicyRefInput",
    "VpnFailoverGroupRefInput",
    "VpnFilteredPageInput",
    "VpnPageInput",
    "VpnPolicyBasedConnectionRefInput",
    "VpnProfileRefInput",
    "VpnRemoteAccessPolicyRefInput",
    "VpnRouteBasedConnectionRefInput",
]

#: The eight clientless bookmark protocols the API discriminates on.
BookmarkProtocol = Literal["rdp", "telnet", "ssh", "ftp", "ftps", "sftp", "smb", "vnc"]

#: Protocol keys the bookmark projection flattens; the value is the protocol payload.
_BOOKMARK_PROTOCOL_KEYS: tuple[str, ...] = (
    "rdp",
    "telnet",
    "ssh",
    "ftp",
    "ftps",
    "sftp",
    "smb",
    "vnc",
)

#: Bookmark protocol members copied verbatim onto the flat projection.
_BOOKMARK_DETAIL_FIELDS: tuple[str, ...] = (
    "url",
    "port",
    "shareSession",
    "protocolSecurity",
    "domain",
    "username",
    "authenticationMethod",
    "initialDirectory",
    "publicHostKey",
)

EncryptionAlgorithm = Literal[
    "Serpent",
    "BlowFish",
    "DES",
    "3DES",
    "TwoFish",
    "AES128",
    "AES192",
    "AES256",
    "AES128GCM16",
    "AES192GCM16",
    "AES256GCM16",
    "AES128GMAC",
    "AES192GMAC",
    "AES256GMAC",
]
AuthenticationAlgorithm = Literal["MD5", "SHA1", "SHA2_256", "SHA2_384", "SHA2_512"]
DhGroup = Literal[
    "DH768",
    "DH1024",
    "DH1536",
    "DH2048",
    "DH3072",
    "DH4096",
    "DH6144",
    "DH8192",
    "ECP256",
    "ECP384",
    "ECP521",
    "ECP192",
    "ECP224",
    "ECP224BP",
    "ECP256BP",
    "ECP384BP",
    "ECP512BP",
    "CURVE25519",
]
Phase2DhGroup = Literal[
    "none",
    "sameAsPhaseOne",
    "DH768",
    "DH1024",
    "DH1536",
    "DH2048",
    "DH3072",
    "DH4096",
    "DH6144",
    "DH8192",
    "ECP256",
    "ECP384",
    "ECP521",
    "ECP192",
    "ECP224",
    "ECP224BP",
    "ECP256BP",
    "ECP384BP",
    "ECP512BP",
    "CURVE25519",
]
DeadPeerAction = Literal["disconnect", "hold", "reInitiate"]
IpsecAuthenticationMethod = Literal["preSharedKey", "certificate", "rsaKey"]
GatewayType = Literal["initiator", "responder", "disable"]
ConnectionType = Literal["policyBased", "routeBased"]
LiveConnectionType = Literal["routeBased", "policyBased"]
IkeVersion = Literal["ikev1", "ikev2"]
SslVpnProtocol = Literal["tcp", "udp"]
SslVpnLeaseMode = Literal["ipv4Only", "ipv4AndIpv6"]
SslVpnEncryptionAlgorithm = Literal[
    "aes128Gcm",
    "aes192Gcm",
    "aes256Gcm",
    "aes128Cbc",
    "aes192Cbc",
    "aes256Cbc",
    "desEde3Cbc",
    "bfCbc",
]
SslVpnAuthenticationAlgorithm = Literal["sha512", "sha384", "sha256", "sha1", "md5"]


class _Output(BaseModel):
    """Base for response projections: unknown server fields are ignored, never echoed.

    The epoch "never" sentinel is published as ``null`` (L6); see
    :func:`~sophos_firewall_mcp.models.objects.serialize_epoch_sentinel`.
    """

    model_config = ConfigDict(extra="ignore")

    @field_serializer(
        "createdAt", "updatedAt", "created_at", "updated_at", check_fields=False, when_used="json"
    )
    def _epoch_sentinel_is_absent(self, value: datetime | None) -> datetime | None:
        """Publish the appliance's epoch "never" sentinel as ``None`` (L6)."""
        return serialize_epoch_sentinel(value)


class _Input(BaseModel):
    """Base for closed request models: the API is closed, unknown fields are a bug."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


# -- Request models --------------------------------------------------------------------


class VpnPageInput(_Input):
    """One page of a paginated VPN collection.

    The bounds mirror the API and the client-side validation: ``page >= 1`` and
    ``1 <= pageSize <= 100``. Only the operations whose contract declares
    ``page``/``pageSize``/``pageTotal`` accept this model.

    ``page_size`` defaults to 10: a default call must stay small enough for a model
    context, and the caller raises it explicitly when it wants a bigger page.
    """

    page: int = Field(
        default=1,
        ge=1,
        description="1-based page number; 0 is rejected before the request is sent.",
    )
    page_size: int = Field(
        default=10,
        ge=1,
        le=100,
        validation_alias=AliasChoices("page_size", "pageSize"),
        serialization_alias="pageSize",
        description=(
            "Page size, 1-100. Defaults to 10 so a default call stays small; raise it "
            "explicitly for a bigger page."
        ),
    )
    page_total: bool = Field(
        default=False,
        validation_alias=AliasChoices("page_total", "pageTotal"),
        serialization_alias="pageTotal",
        description=(
            "Also request pages.total (the number of pages) and pages.items (the number "
            "of items) in the response metadata."
        ),
    )


class VpnFilteredPageInput(VpnPageInput):
    """A page plus the ``nameContains``/``nameNotEquals`` filters the API declares."""

    name_contains: str | None = Field(
        default=None,
        validation_alias=AliasChoices("name_contains", "nameContains"),
        serialization_alias="nameContains",
        min_length=1,
        max_length=255,
        description="Only return objects whose name contains this text.",
    )
    name_not_equals: str | None = Field(
        default=None,
        validation_alias=AliasChoices("name_not_equals", "nameNotEquals"),
        serialization_alias="nameNotEquals",
        min_length=1,
        max_length=255,
        description="Exclude the object with exactly this name.",
    )

    @model_validator(mode="after")
    def _at_most_one_name_filter(self) -> "VpnFilteredPageInput":
        """Reject both name filters: the API declares them mutually exclusive."""
        if self.name_contains is not None and self.name_not_equals is not None:
            raise ValueError(
                "name_contains and name_not_equals are mutually exclusive; set at most one"
            )
        return self

    def name_filters(self) -> dict[str, str]:
        """The declared name filters, omitting the ones the caller did not set."""
        filters: dict[str, str] = {}
        if self.name_contains is not None:
            filters["nameContains"] = self.name_contains
        if self.name_not_equals is not None:
            filters["nameNotEquals"] = self.name_not_equals
        return filters


class FailoverGroupListInput(VpnFilteredPageInput):
    """A page of failover groups.

    ``getFailovergroups`` also declares opaque ``filter`` and ``sort`` query parameters;
    the API documents no grammar for them, so they are passed through verbatim.
    """

    filter: str | None = Field(
        default=None, description="Appliance-defined filter expression (no documented grammar)."
    )
    sort: str | None = Field(
        default=None, description="Appliance-defined sort expression (no documented grammar)."
    )

    def extra_filters(self) -> dict[str, str]:
        """The declared ``filter``/``sort`` parameters, omitting the ones not set."""
        filters: dict[str, str] = {}
        if self.filter is not None:
            filters["filter"] = self.filter
        if self.sort is not None:
            filters["sort"] = self.sort
        return filters


class VpnProfileRefInput(_Input):
    """Identify one IPsec profile by name or UUID."""

    id_or_name: Annotated[ObjectNameOrId, Field(min_length=1, max_length=50)] = Field(
        validation_alias=AliasChoices("id_or_name", "idOrName"),
        serialization_alias="idOrName",
        description="Profile name or UUID.",
    )


class VpnFailoverGroupRefInput(_Input):
    """Identify one IPsec failover group by name or UUID."""

    id_or_name: Annotated[ObjectNameOrId, Field(min_length=1, max_length=50)] = Field(
        validation_alias=AliasChoices("id_or_name", "idOrName"),
        serialization_alias="idOrName",
        description="Failover group name or UUID.",
    )


class VpnPolicyBasedConnectionRefInput(_Input):
    """Identify one policy-based IPv4 site-to-site connection by name or UUID."""

    id_or_name: Annotated[ObjectNameOrId, Field(min_length=1, max_length=100)] = Field(
        validation_alias=AliasChoices("id_or_name", "idOrName"),
        serialization_alias="idOrName",
        description="Connection name or UUID.",
    )


class VpnRouteBasedConnectionRefInput(_Input):
    """Identify one route-based IPv4 site-to-site connection by name or UUID."""

    id_or_name: Annotated[ObjectNameOrId, Field(min_length=1, max_length=100)] = Field(
        validation_alias=AliasChoices("id_or_name", "idOrName"),
        serialization_alias="idOrName",
        description="Connection name or UUID.",
    )


class VpnRemoteAccessPolicyRefInput(_Input):
    """Identify one SSL VPN remote-access policy by name or UUID."""

    id_or_name: Annotated[ObjectNameOrId, Field(min_length=1, max_length=50)] = Field(
        validation_alias=AliasChoices("id_or_name", "idOrName"),
        serialization_alias="idOrName",
        description="Policy name or UUID.",
    )


class VpnBookmarkGroupRefInput(_Input):
    """Identify one clientless bookmark group by name or UUID."""

    id_or_name: Annotated[ObjectNameOrId, Field(min_length=1, max_length=50)] = Field(
        validation_alias=AliasChoices("id_or_name", "idOrName"),
        serialization_alias="idOrName",
        description="Bookmark group name or UUID.",
    )


class VpnBookmarkRefInput(_Input):
    """Identify one clientless bookmark by name or UUID."""

    id_or_name: Annotated[ObjectNameOrId, Field(min_length=1, max_length=50)] = Field(
        validation_alias=AliasChoices("id_or_name", "idOrName"),
        serialization_alias="idOrName",
        description="Bookmark name or UUID.",
    )


class VpnClientlessPolicyRefInput(_Input):
    """Identify one clientless policy by name or UUID."""

    id_or_name: Annotated[ObjectNameOrId, Field(min_length=1, max_length=50)] = Field(
        validation_alias=AliasChoices("id_or_name", "idOrName"),
        serialization_alias="idOrName",
        description="Clientless policy name or UUID.",
    )


# -- IPsec profiles --------------------------------------------------------------------


class IpsecPhase1Algorithm(_Output):
    """One phase-1 encryption/authentication proposal."""

    encryptionAlgorithm: EncryptionAlgorithm | None = None
    authenticationAlgorithm: AuthenticationAlgorithm | None = None


class IpsecPhase2Algorithm(_Output):
    """One phase-2 encryption/authentication proposal."""

    encryptionAlgorithm: EncryptionAlgorithm | None = None
    authenticationAlgorithm: AuthenticationAlgorithm | None = None


class IpsecPhase1(_Output):
    """Phase-1 (IKE SA) settings of an IPsec profile."""

    dhGroup: list[DhGroup] = Field(default_factory=list)
    keyLife: int | None = None
    rekeyMargin: int | None = None
    rekeyFuzz: int | None = None
    algorithms: list[IpsecPhase1Algorithm] = Field(default_factory=list)


class IpsecPhase2(_Output):
    """Phase-2 (IPsec SA) settings of an IPsec profile."""

    dhGroup: Phase2DhGroup | None = None
    keyLife: int | None = None
    algorithms: list[IpsecPhase2Algorithm] = Field(default_factory=list)


class IpsecDeadPeerDetection(_Output):
    """Dead-peer-detection settings of an IPsec profile."""

    enabled: bool | None = None
    delay: int | None = None
    timeout: int | None = None
    action: DeadPeerAction | None = None


class IpsecProfile(_Output):
    """One IPsec profile."""

    id: str | None = None
    name: str | None = None
    description: str | None = None
    keyExchange: IkeVersion | None = None
    authenticationMode: Literal["main", "aggressive"] | None = None
    keyNegotiationTries: int | None = None
    rekeyEnabled: bool | None = None
    strictProfileEnabled: bool | None = None
    compressionEnabled: bool | None = None
    sha2TruncateEnabled: bool | None = None
    phase1: IpsecPhase1 | None = None
    phase2: IpsecPhase2 | None = None
    deadPeerDetection: IpsecDeadPeerDetection | None = None
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


# -- IPsec failover groups -------------------------------------------------------------


class LivenessCheck(_Output):
    """One failover-group liveness check."""

    protocol: Literal["tcp", "ping"] | None = None
    port: int | None = None


class IpsecFailoverGroup(_Output):
    """One IPsec site-to-site failover group."""

    id: str | None = None
    name: str | None = None
    activateFailoverGroup: bool | None = None
    mailAlertEnabled: bool | None = None
    failbackEnabled: bool | None = None
    ipsecConnections: list[ObjectRef] = Field(default_factory=list)
    livenessChecks: list[LivenessCheck] = Field(default_factory=list)
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


# -- IPsec site-to-site connections ----------------------------------------------------


class IpsecPeerId(_Output):
    """A local or remote peer identity.

    The API uses two different ``type`` enums for this field (``dns``/``fqdn`` plus
    ``ip``/``email``/``x509``), so it is carried as a string rather than a ``Literal``.
    """

    type: str | None = None
    value: str | None = None


class IpsecRemoteGateway(_Output):
    """The remote gateway of a site-to-site connection: any peer, an IPv4 address or an FQDN."""

    any: bool | None = None
    ipv4Address: str | None = None
    fqdn: str | None = None


class IpsecGatewaySettings(_Output):
    """Gateway settings of a site-to-site connection.

    The API models preshared-key, certificate and RSA-key authentication as three
    ``oneOf`` variants; this projection carries the union of their response fields. A
    preshared key is never returned by the appliance -- only ``preSharedKeyConfigured``.
    """

    authentication: IpsecAuthenticationMethod | None = None
    localGateway: ObjectRef | None = None
    remoteGateway: IpsecRemoteGateway | None = None
    localId: IpsecPeerId | None = None
    remoteId: IpsecPeerId | None = None
    preSharedKeyConfigured: bool | None = None
    localCertificate: ObjectRef | None = None
    remoteCertificate: ObjectRef | None = None
    remoteCaCertificate: ObjectRef | None = None
    remoteRsaKey: str | None = None


class IpsecNetworkAddress(_Output):
    """One protected network reference, with its optional NAT address."""

    ipv4Address: ObjectRef | None = None
    ipv4NatAddress: ObjectRef | None = None
    ipv6Address: ObjectRef | None = None
    ipv6NatAddress: ObjectRef | None = None


class IpsecNetworkSelector(_Output):
    """A protected-network selector: ``any`` or explicit address objects."""

    any: bool | None = None
    ipv4Addresses: list[IpsecNetworkAddress] = Field(default_factory=list)
    ipv6Addresses: list[ObjectRef] = Field(default_factory=list)


class IpsecProtectedNetworks(_Output):
    """The local and remote networks protected by a site-to-site connection."""

    localNetworksIpv4: IpsecNetworkSelector | None = None
    localNetworksIpv6: IpsecNetworkSelector | None = None
    remoteNetworksIpv4: IpsecNetworkSelector | None = None
    remoteNetworksIpv6: IpsecNetworkSelector | None = None


class IpsecConnection(_Output):
    """One configured IPv4 site-to-site connection (policy-based or route-based)."""

    id: str | None = None
    name: str | None = None
    description: str | None = None
    type: ConnectionType | None = None
    gatewayType: GatewayType | None = None
    profile: ObjectRef | None = None
    gatewaySettings: IpsecGatewaySettings | None = None
    protectedNetworks: IpsecProtectedNetworks | None = None
    activateConnection: bool | None = None
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


class IpsecRouteBasedConnection(_Output):
    """One configured route-based IPv4 site-to-site connection (adds the tunnel interface)."""

    id: str | None = None
    name: str | None = None
    description: str | None = None
    gatewayType: GatewayType | None = None
    profile: ObjectRef | None = None
    tunnelInterface: ObjectRef | None = None
    gatewaySettings: IpsecGatewaySettings | None = None
    protectedNetworks: IpsecProtectedNetworks | None = None
    activateConnection: bool | None = None
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


class IpsecTrafficSelector(_Output):
    """One traffic selector of a live IPsec SA: an IPv4 pair or an IPv6 pair."""

    localNetworkIpv4: str | None = None
    remoteNetworkIpv4: str | None = None
    localNetworkIpv6: str | None = None
    remoteNetworkIpv6: str | None = None


class IpsecSecurityAssociation(_Output):
    """One live IPsec security association and its traffic counters."""

    ipsecSecurityAssociationId: int | None = None
    name: str | None = None
    trafficSelectors: IpsecTrafficSelector | None = None
    packetsSent: int | None = None
    packetsReceived: int | None = None
    bytesSent: int | None = None
    bytesReceived: int | None = None


class IkeSecurityAssociation(_Output):
    """One live IKE security association and the IPsec SAs established under it."""

    ikeSecurityAssociationId: int | None = None
    name: str | None = None
    localId: str | None = None
    remoteId: str | None = None
    localGatewayIpv4: str | None = None
    remoteGatewayIpv4: str | None = None
    ikeVersion: IkeVersion | None = None
    ipsecSecurityAssociations: list[IpsecSecurityAssociation] = Field(default_factory=list)


class IpsecLiveConnection(_Output):
    """One live site-to-site connection (operational state, not configuration)."""

    connectionName: str | None = None
    type: LiveConnectionType | None = None
    ikeSecurityAssociation: IkeSecurityAssociation | None = None
    additionalIkeSecurityAssociations: list[IkeSecurityAssociation] = Field(default_factory=list)


# -- IPsec remote access ---------------------------------------------------------------


class IpsecUsersOrGroups(_Output):
    """Users and user groups authorized for remote-access IPsec."""

    users: list[ObjectRef] = Field(default_factory=list)
    userGroups: list[ObjectRef] = Field(default_factory=list)


class IpsecLeaseConfigurationIpv4(_Output):
    """IPv4 lease range for remote-access IPsec clients."""

    startAddressIpv4: str | None = None
    endAddressIpv4: str | None = None
    leaseFromRadius: bool | None = None


class RemoteAccessProtectedNetworks(_Output):
    """Networks reachable through remote-access IPsec."""

    fullTunnel: bool | None = None
    localNetworksIpv4: IpsecNetworkSelector | None = None


class SophosConnectAutoConnect(_Output):
    """Sophos Connect auto-connect settings."""

    enabled: bool | None = None
    monitoringHost: IpsecRemoteGateway | None = None


class SophosConnectClientSettings(_Output):
    """Settings pushed to the Sophos Connect client."""

    saveCredentials: bool | None = None
    twoFactorTokenPrompt: bool | None = None
    invokeLogonScript: bool | None = None
    autoConnect: SophosConnectAutoConnect | None = None


class IpsecRemoteAccessSettings(_Output):
    """The remote-access IPsec configuration (a single settings object).

    ``configured`` is derived, not returned by the appliance. The API requires
    ``connectionState`` and uses ``"unset"`` to mean "remote-access IPsec is not configured
    at all", so the projection lifts that sentinel into a boolean an agent can branch on
    without knowing it: ``configured`` is true only for ``enabled`` and ``disabled``. An
    unset configuration is otherwise an object whose every other member is null.
    """

    configured: bool = False
    name: str | None = None
    connectionState: Literal["unset", "enabled", "disabled"] | None = None
    profile: ObjectRef | None = None
    gatewaySettings: IpsecGatewaySettings | None = None
    usersOrGroups: IpsecUsersOrGroups | None = None
    leaseConfigurationIpv4: IpsecLeaseConfigurationIpv4 | None = None
    primaryDnsIpv4: str | None = None
    secondaryDnsIpv4: str | None = None
    dnsSuffix: str | None = None
    idlePeerDetection: bool | None = None
    idlePeerDetectionTimeout: int | None = None
    protectedNetworks: RemoteAccessProtectedNetworks | None = None
    sophosConnectClientSettings: SophosConnectClientSettings | None = None
    updatedAt: datetime | None = None

    @model_validator(mode="after")
    def _derive_configured(self) -> Self:
        """Derive ``configured`` from the required ``connectionState``.

        ``"unset"`` is the appliance's "never configured" sentinel, so it maps to false;
        ``"enabled"`` and ``"disabled"`` both mean a configuration exists. A missing
        ``connectionState`` violates the API and is reported as not configured rather
        than guessed as configured.
        """
        self.configured = self.connectionState in ("enabled", "disabled")
        return self


# -- SSL VPN ---------------------------------------------------------------------------


class SslVpnPolicyMembers(_Output):
    """Users and user groups assigned to an SSL VPN remote-access policy."""

    users: list[ObjectRef] = Field(default_factory=list)
    userGroups: list[ObjectRef] = Field(default_factory=list)


class SslVpnPermittedNetworksIpv4(_Output):
    """IPv4 destinations permitted by an SSL VPN remote-access policy."""

    ipv4Addresses: list[ObjectRef] = Field(default_factory=list)
    fqdnAddresses: list[ObjectRef] = Field(default_factory=list)
    fqdnGroups: list[ObjectRef] = Field(default_factory=list)


class SslVpnPermittedNetworksIpv6(_Output):
    """IPv6 destinations permitted by an SSL VPN remote-access policy."""

    ipv6Addresses: list[ObjectRef] = Field(default_factory=list)


class SslVpnRemoteAccessPolicy(_Output):
    """One SSL VPN remote-access policy."""

    id: str | None = None
    name: str | None = None
    description: str | None = None
    policyMembers: SslVpnPolicyMembers | None = None
    fullTunnel: bool | None = None
    permittedNetworksIpv4: SslVpnPermittedNetworksIpv4 | None = None
    permittedNetworksIpv6: SslVpnPermittedNetworksIpv6 | None = None
    idlePeerDetection: bool | None = None
    overrideIdlePeerDetectionTimeout: int | None = None
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


class SslVpnBookmark(_Output):
    """One clientless SSL VPN bookmark, flattened across the eight protocol variants.

    The API models a bookmark as an ``oneOf`` over ``rdp``, ``telnet``, ``ssh``,
    ``ftp``, ``ftps``, ``sftp``, ``smb`` and ``vnc`` payloads. This projection lifts the
    single protocol key into ``protocol`` and copies the protocol members that are common
    to the variants, so the model sees one flat object instead of eight shapes. Credentials
    are never returned by the appliance; only the login user name is.
    """

    id: str | None = None
    name: str | None = None
    description: str | None = None
    protocol: BookmarkProtocol | None = None
    url: str | None = None
    port: int | None = None
    shareSession: bool | None = None
    protocolSecurity: Literal["rdp", "tls", "nla"] | None = None
    domain: str | None = None
    username: str | None = None
    authenticationMethod: str | None = None
    initialDirectory: str | None = None
    publicHostKey: str | None = None
    automaticLoginUsername: str | None = None
    createdAt: datetime | None = None
    updatedAt: datetime | None = None

    @model_validator(mode="before")
    @classmethod
    def _flatten_protocol_payload(cls, data: Any) -> Any:
        """Lift the single protocol payload of a bookmark onto the flat projection."""
        if not isinstance(data, dict):
            return data
        for protocol in _BOOKMARK_PROTOCOL_KEYS:
            details = data.get(protocol)
            if not isinstance(details, dict):
                continue
            flattened = {
                key: value for key, value in data.items() if key not in _BOOKMARK_PROTOCOL_KEYS
            }
            flattened["protocol"] = protocol
            for field_name in _BOOKMARK_DETAIL_FIELDS:
                if field_name in details:
                    flattened[field_name] = details[field_name]
            automatic_login = details.get("automaticLogin")
            if isinstance(automatic_login, dict):
                if "username" in automatic_login:
                    flattened["automaticLoginUsername"] = automatic_login["username"]
                if "authenticationMethod" in automatic_login:
                    flattened.setdefault(
                        "authenticationMethod", automatic_login["authenticationMethod"]
                    )
            return flattened
        return data


class SslVpnBookmarkGroup(_Output):
    """One clientless bookmark group."""

    id: str | None = None
    name: str | None = None
    description: str | None = None
    bookmarks: list[ObjectRef] = Field(default_factory=list)
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


class SslVpnUsersOrGroups(_Output):
    """Policy members of a clientless policy: users and groups."""

    users: list[ObjectRef] = Field(default_factory=list)
    groups: list[ObjectRef] = Field(default_factory=list)


class SslVpnPublishedBookmarks(_Output):
    """Bookmarks and bookmark groups published by a clientless policy."""

    bookmarks: list[ObjectRef] = Field(default_factory=list)
    bookmarkGroups: list[ObjectRef] = Field(default_factory=list)


class SslVpnClientlessPolicy(_Output):
    """One SSL VPN Web Access (clientless) policy."""

    id: str | None = None
    name: str | None = None
    description: str | None = None
    usersOrGroups: SslVpnUsersOrGroups | None = None
    publishedBookmarks: SslVpnPublishedBookmarks | None = None
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


class SslVpnOverrideHost(_Output):
    """The hostname or address that replaces the firewall's default interface addresses."""

    ipv4Address: str | None = None
    ipv6Address: str | None = None
    fqdn: str | None = None


class SslVpnLease(_Output):
    """One SSL VPN client address lease pool."""

    networkAddress: str | None = None
    prefix: int | None = None


class SslVpnCryptographicSettings(_Output):
    """Cryptographic settings of the SSL VPN portal."""

    encryptionAlgorithm: SslVpnEncryptionAlgorithm | None = None
    authenticationAlgorithm: SslVpnAuthenticationAlgorithm | None = None
    keySize: int | None = None
    keyLifetime: int | None = None


class SslVpnGlobalSettings(_Output):
    """The SSL VPN global settings (a single settings object)."""

    protocol: SslVpnProtocol | None = None
    port: int | None = None
    serverCertificate: ObjectRef | None = None
    overrideHost: SslVpnOverrideHost | None = None
    leaseIpv4: SslVpnLease | None = None
    leaseIpv6: SslVpnLease | None = None
    leaseMode: SslVpnLeaseMode | None = None
    staticIpLease: bool | None = None
    primaryDnsIpv4: str | None = None
    secondaryDnsIpv4: str | None = None
    primaryWinsIpv4: str | None = None
    secondaryWinsIpv4: str | None = None
    dnsSuffix: str | None = None
    deadPeerDetectionTimeout: int | None = None
    idlePeerDetectionTimeout: int | None = None
    cryptographicSettings: SslVpnCryptographicSettings | None = None
    sophosConnectClientSettings: SophosConnectClientSettings | None = None
    updatedAt: datetime | None = None
