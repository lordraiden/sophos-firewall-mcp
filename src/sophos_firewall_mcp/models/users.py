"""Pydantic models for the Sophos Firewall authentication-user and live-session domain.

The contract keeps three families apart, and so does this module (#30):

* **general authentication users** -- ``getUsers`` returns a paginated *basic summary* that
  also reports ``administrativeAccess``; it is a read-only view in v1;
* **network users** -- ``getNetworkUsers``/``getNetworkUser``/``createNetworkUser``/
  ``updateNetworkUser``/``deleteNetworkUser`` are the account CRUD surface, with policies
  and VPN access;
* **live sessions** -- ``getLiveUsers``/``disconnectLiveUser`` operate on active sessions,
  not on accounts.

Credentials are write-only. The create/update inputs accept ``password`` as a
:class:`~pydantic.SecretStr`, no output model has a credential field, and the ``*Wire``
models that parse appliance payloads expose none either. Administrators and user groups are
out of the v1 scope and have no model here.

The ``*Wire`` models parse the appliance payload (``extra="ignore"``, forward-compatible)
and are never returned to a model; the ``project_*`` functions turn them into the bounded
snake_case DTOs the tools publish.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Annotated, Any, Literal, Mapping

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    model_validator,
)

from sophos_firewall_mcp.models.common import ListPage, validate_object_name

__all__ = [
    "LIVE_USER_CLIENT_TYPES",
    "AllowedNetworksIpv4Input",
    "LiveUserDisconnectInput",
    "LiveUserDisconnectOutput",
    "LiveUserListInput",
    "LiveUserSessionOutput",
    "LiveUserSessionWire",
    "NetworkUserCreateInput",
    "NetworkUserDeleteInput",
    "NetworkUserDeleteOutput",
    "NetworkUserGetInput",
    "NetworkUserListInput",
    "NetworkUserOutput",
    "NetworkUserPoliciesInput",
    "NetworkUserPoliciesOutput",
    "NetworkUserPoliciesWire",
    "NetworkUserUpdateInput",
    "NetworkUserVpnAccessInput",
    "NetworkUserVpnAccessOutput",
    "NetworkUserVpnAccessWire",
    "NetworkUserWire",
    "PolicyRefInput",
    "SimultaneousLoginsInput",
    "UserListInput",
    "UserSummaryOutput",
    "UserSummaryWire",
    "project_live_user_page",
    "project_network_user",
    "project_network_user_page",
    "project_user_page",
    "validate_object_name_or_id",
]

#: The 20 ``clientType`` values the contract declares for a live session. The output model
#: keeps ``client_type`` a plain ``str`` so a future firmware value is passed through
#: instead of failing the whole listing; this constant is the documented vocabulary and is
#: asserted against the contract by the tests.
LIVE_USER_CLIENT_TYPES = frozenset(
    {
        "adSsoKerberos",
        "adSsoNtlm",
        "androidClient",
        "androidWebClient",
        "api",
        "authenticationAgent",
        "chromebookSso",
        "clientless",
        "heartbeat",
        "ipsecVpn",
        "iosClient",
        "iosWebClient",
        "l2tpVpn",
        "multiHostClient",
        "pptpVpn",
        "radiusSso",
        "sslVpnTunnel",
        "stas",
        "thinClient",
        "webClient",
    }
)

#: UUID shape of the ``sfos-object-name-or-id`` format (the YAML ``format`` carries no
#: assertion, so the model enforces it).
_UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

#: Sequences the shared REST client refuses in a path. ``quote(..., safe="")`` encodes
#: ``?``, ``#``, ``/`` and ``\\`` but leaves ``.`` untouched, so a name containing ``..``
#: cannot be addressed through the transport and is rejected here with a clear message
#: instead of surfacing as an unexpected client ``ValueError``.
_UNSAFE_PATH_SEQUENCES = ("..", "\\", "?", "#", "://", "%2e")


def _validate_ipv4(value: str) -> str:
    """Validate the contract's ``ipv4`` format."""
    try:
        ipaddress.IPv4Address(value)
    except ValueError as exc:
        raise ValueError("must be a valid IPv4 address") from exc
    return value


def _validate_ipv6(value: str) -> str:
    """Validate the contract's ``ipv6`` format."""
    try:
        ipaddress.IPv6Address(value)
    except ValueError as exc:
        raise ValueError("must be a valid IPv6 address") from exc
    return value


def validate_object_name_or_id(value: str) -> str:
    """Validate the documented ``sfos-object-name-or-id`` path format.

    A UUID is accepted as-is; anything else must be a valid ``sfos-object-name`` and must be
    addressable through the shared REST client (no ``..`` and no other path-significant
    sequence).

    Raises:
        ValueError: The value is neither a UUID nor an addressable object name.
    """
    if not isinstance(value, str):
        raise ValueError("identifier must be a string")
    if _UUID_PATTERN.match(value):
        return value
    validate_object_name(value)
    lowered = value.lower()
    for sequence in _UNSAFE_PATH_SEQUENCES:
        if sequence in lowered:
            raise ValueError(
                f"object name must not contain {sequence!r}: it is not addressable as a "
                "path segment; use the object's UUID instead"
            )
    return value


#: ``str`` annotated with the documented ``sfos-object-name-or-id`` validation.
ObjectNameOrId = Annotated[str, AfterValidator(validate_object_name_or_id)]

#: Network-user login name: ``sfos-object-name``, at most 50 characters (create body).
NetworkUserName = Annotated[
    str, Field(min_length=1, max_length=50), AfterValidator(validate_object_name)
]

#: User-group reference name: ``sfos-object-name``, at most 256 characters.
UserGroupName = Annotated[
    str, Field(min_length=1, max_length=256), AfterValidator(validate_object_name)
]

#: Policy reference name: ``sfos-object-name``, at most 60 characters.
PolicyName = Annotated[
    str, Field(min_length=1, max_length=60), AfterValidator(validate_object_name)
]

#: IPv4 address string, at most 15 characters (contract ``format: ipv4``).
Ipv4Address = Annotated[str, Field(max_length=15), AfterValidator(_validate_ipv4)]

#: IPv6 address string, at most 45 characters (contract ``format: ipv6``).
Ipv6Address = Annotated[str, Field(max_length=45), AfterValidator(_validate_ipv6)]


# -- Inputs: pagination and filters ----------------------------------------------------


class _NameFilterPageInput(BaseModel):
    """The ``page``/``pageSize``/``pageTotal`` plus name-filter query contract.

    Shared by ``getUsers`` and ``getNetworkUsers``; the two operations have the same query
    contract but expose different resources, so each keeps its own public subclass.
    """

    model_config = ConfigDict(extra="forbid")

    page: int = Field(
        default=1,
        ge=1,
        description="1-based page number. The contract declares a minimum of 1.",
    )
    page_size: int = Field(
        default=50,
        ge=1,
        le=100,
        description="Page size; the contract declares a maximum of 100.",
    )
    page_total: bool = Field(
        default=False,
        description="Ask the appliance for pages.total and pages.items metadata.",
    )
    name_contains: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
        description="Only return objects whose name contains this value.",
    )
    name_not_equals: str | None = Field(
        default=None,
        min_length=1,
        max_length=255,
        description="Exclude the object with exactly this name.",
    )

    @model_validator(mode="after")
    def _at_most_one_name_filter(self) -> "_NameFilterPageInput":
        if self.name_contains is not None and self.name_not_equals is not None:
            raise ValueError(
                "name_contains and name_not_equals are mutually exclusive; provide at most one"
            )
        return self


class UserListInput(_NameFilterPageInput):
    """Input of ``getUsers``: the paginated general authentication-user list."""


class NetworkUserListInput(_NameFilterPageInput):
    """Input of ``getNetworkUsers``: the paginated network-user collection."""


# -- Inputs: network-user bodies -------------------------------------------------------


class PolicyRefInput(BaseModel):
    """A policy reference by name, or an explicit ``noPolicy`` marker.

    The contract models this as ``oneOf [{name}, {noPolicy: true}]``; exactly one variant is
    sent, never both and never an empty object.
    """

    model_config = ConfigDict(extra="forbid")

    name: PolicyName | None = Field(default=None, description="Referenced policy name.")
    no_policy: Literal[True] | None = Field(
        default=None,
        serialization_alias="noPolicy",
        description="Set true to explicitly disable the policy.",
    )

    @model_validator(mode="after")
    def _exactly_one_reference(self) -> "PolicyRefInput":
        if (self.name is None) == (self.no_policy is None):
            raise ValueError("set exactly one of name or no_policy")
        return self


class UserGroupRefInput(BaseModel):
    """A user-group reference by name: ``{"name": "<group>"}``.

    The contract models ``group`` as an object with a required ``name`` member, not as a
    bare string. A string is rejected by the appliance with ``400 invalidRequest``
    ("Invalid group."), so the reference object is the only accepted shape.
    """

    model_config = ConfigDict(extra="forbid")

    name: UserGroupName = Field(description="User group name (OUGROUPNAME token).")


class AllowedNetworksIpv4Input(BaseModel):
    """Allowed login networks: any address, a list of addresses, or an inclusive range."""

    model_config = ConfigDict(extra="forbid")

    any: Literal[True] | None = Field(
        default=None, description="Allow login from any IPv4 address."
    )
    ipv4_addresses: list[Ipv4Address] | None = Field(
        default=None,
        min_length=1,
        serialization_alias="ipv4Addresses",
        description="Allow login only from these IPv4 addresses.",
    )
    ipv4_address_start: Ipv4Address | None = Field(
        default=None,
        serialization_alias="ipv4AddressStart",
        description="First address of the allowed inclusive range.",
    )
    ipv4_address_end: Ipv4Address | None = Field(
        default=None,
        serialization_alias="ipv4AddressEnd",
        description="Last address of the allowed inclusive range.",
    )

    @model_validator(mode="after")
    def _exactly_one_variant(self) -> "AllowedNetworksIpv4Input":
        range_set = self.ipv4_address_start is not None or self.ipv4_address_end is not None
        variants = sum((self.any is not None, self.ipv4_addresses is not None, range_set))
        if variants != 1:
            raise ValueError(
                "set exactly one of any, ipv4_addresses, or the "
                "ipv4_address_start/ipv4_address_end range"
            )
        if (self.ipv4_address_start is None) != (self.ipv4_address_end is None):
            raise ValueError("ipv4_address_start and ipv4_address_end must be provided together")
        return self


class SimultaneousLoginsInput(BaseModel):
    """Simultaneous-login override: global limit, unlimited, or a custom limit."""

    model_config = ConfigDict(extra="forbid")

    use_global_limit: Literal[True] | None = Field(
        default=None,
        serialization_alias="useGlobalLimit",
        description="Use the global simultaneous-login limit.",
    )
    unlimited: Literal[True] | None = Field(
        default=None, description="Allow unlimited simultaneous logins."
    )
    limit: int | None = Field(
        default=None,
        ge=1,
        le=99,
        description="Custom simultaneous-login limit.",
    )

    @model_validator(mode="after")
    def _exactly_one_variant(self) -> "SimultaneousLoginsInput":
        variants = sum(
            (self.use_global_limit is not None, self.unlimited is not None, self.limit is not None)
        )
        if variants != 1:
            raise ValueError("set exactly one of use_global_limit, unlimited or limit")
        return self


class NetworkUserPoliciesInput(BaseModel):
    """Policy overrides of a network user; every field is optional (merge-patch friendly)."""

    model_config = ConfigDict(extra="forbid")

    surfing_quota_policy: PolicyRefInput | None = Field(
        default=None, serialization_alias="surfingQuotaPolicy"
    )
    access_time_policy: PolicyRefInput | None = Field(
        default=None, serialization_alias="accessTimePolicy"
    )
    network_traffic_quota_policy: PolicyRefInput | None = Field(
        default=None, serialization_alias="networkTrafficQuotaPolicy"
    )
    traffic_shaping_policy: PolicyRefInput | None = Field(
        default=None, serialization_alias="trafficShapingPolicy"
    )
    mac_binding: bool | None = Field(default=None, serialization_alias="macBinding")
    mac_addresses: list[str] | None = Field(default=None, serialization_alias="macAddresses")
    allowed_networks_ipv4: AllowedNetworksIpv4Input | None = Field(
        default=None, serialization_alias="allowedNetworksIpv4"
    )
    simultaneous_logins: SimultaneousLoginsInput | None = Field(
        default=None, serialization_alias="simultaneousLogins"
    )


class NetworkUserVpnAccessInput(BaseModel):
    """Optional VPN-access overrides of a network user."""

    model_config = ConfigDict(extra="forbid")

    ssl_vpn_remote_access_policy: PolicyRefInput | None = Field(
        default=None, serialization_alias="sslVpnRemoteAccessPolicy"
    )
    ssl_vpn_clientless_policy: PolicyRefInput | None = Field(
        default=None, serialization_alias="sslVpnClientlessPolicy"
    )
    ssl_vpn_static_ipv4_address: Ipv4Address | None = Field(
        default=None, serialization_alias="sslVpnStaticIpv4Address"
    )
    ssl_vpn_static_ipv6_address: Ipv6Address | None = Field(
        default=None, serialization_alias="sslVpnStaticIpv6Address"
    )
    l2tp: bool | None = None
    l2tp_static_ipv4_address: Ipv4Address | None = Field(
        default=None, serialization_alias="l2tpStaticIpv4Address"
    )
    pptp: bool | None = None
    pptp_static_ipv4_address: Ipv4Address | None = Field(
        default=None, serialization_alias="pptpStaticIpv4Address"
    )
    ipsec_vpn_remote_access: bool | None = Field(
        default=None, serialization_alias="ipsecVpnRemoteAccess"
    )
    ipsec_vpn_static_ipv4_address: Ipv4Address | None = Field(
        default=None, serialization_alias="ipsecVpnStaticIpv4Address"
    )


class NetworkUserCreateInput(BaseModel):
    """Body of ``createNetworkUser``: ``name``, ``displayName``, ``password`` and ``group``
    are required by the contract; everything else is optional.

    ``password`` is a :class:`~pydantic.SecretStr`: it is sent once, never returned, never
    logged and never included in an error message.
    """

    model_config = ConfigDict(extra="forbid")

    name: NetworkUserName = Field(description="Unique login name of the network user.")
    display_name: str = Field(
        min_length=1,
        max_length=50,
        serialization_alias="displayName",
        description="Display name of the network user.",
    )
    password: SecretStr = Field(
        min_length=1,
        max_length=50,
        description="Write-only login password; never returned or logged.",
    )
    group: UserGroupRefInput = Field(
        description="Primary user group of the network user, as a `{name}` reference."
    )
    description: str | None = Field(default=None, description="Free-text description.")
    active: bool | None = Field(default=None, description="Whether the account is active.")
    email_addresses: list[str] | None = Field(default=None, serialization_alias="emailAddresses")
    policies: NetworkUserPoliciesInput | None = None
    vpn_access: NetworkUserVpnAccessInput | None = Field(
        default=None, serialization_alias="vpnAccess"
    )
    email_quarantine_digest: bool | None = Field(
        default=None, serialization_alias="emailQuarantineDigest"
    )


class NetworkUserUpdateInput(BaseModel):
    """Body of ``updateNetworkUser`` (PATCH, JSON Merge Patch).

    Only the fields the caller sets are sent: omitted fields keep their stored value and an
    explicit ``null`` removes a property (RFC 7396). At least one body field is required so
    the tool never sends an empty merge patch.
    """

    model_config = ConfigDict(extra="forbid")

    id_or_name: ObjectNameOrId = Field(description="Name or UUID of the network user to update.")
    display_name: str | None = Field(
        default=None,
        min_length=1,
        max_length=50,
        serialization_alias="displayName",
        description="Display name of the network user.",
    )
    password: SecretStr | None = Field(
        default=None,
        min_length=1,
        max_length=50,
        description="Write-only new password; never returned or logged.",
    )
    description: str | None = Field(default=None, description="Free-text description.")
    active: bool | None = Field(default=None, description="Whether the account is active.")
    email_addresses: list[str] | None = Field(default=None, serialization_alias="emailAddresses")
    group: UserGroupRefInput | None = Field(
        default=None, description="Primary user group, as a `{name}` reference."
    )
    policies: NetworkUserPoliciesInput | None = None
    vpn_access: NetworkUserVpnAccessInput | None = Field(
        default=None, serialization_alias="vpnAccess"
    )
    email_quarantine_digest: bool | None = Field(
        default=None, serialization_alias="emailQuarantineDigest"
    )

    @model_validator(mode="after")
    def _at_least_one_update(self) -> "NetworkUserUpdateInput":
        if not (self.model_fields_set - {"id_or_name"}):
            raise ValueError("provide at least one field to update")
        if "password" in self.model_fields_set and self.password is None:
            raise ValueError("password cannot be null; omit it to keep the current password")
        return self


class NetworkUserGetInput(BaseModel):
    """Input of ``getNetworkUser``."""

    model_config = ConfigDict(extra="forbid")

    id_or_name: ObjectNameOrId = Field(description="Name or UUID of the network user.")


class NetworkUserDeleteInput(BaseModel):
    """Input of ``deleteNetworkUser``."""

    model_config = ConfigDict(extra="forbid")

    id_or_name: ObjectNameOrId = Field(description="Name or UUID of the network user.")


# -- Inputs: live sessions -------------------------------------------------------------


class LiveUserListInput(BaseModel):
    """Input of ``getLiveUsers``.

    The contract declares no request parameters for ``/authentication/live-users``. The
    appliance accepts ``page``/``pageSize``/``pageTotal`` (live observation, 2026-11-15) but
    v1 does not expose them, so this input is deliberately empty and closed.
    """

    model_config = ConfigDict(extra="forbid")


class LiveUserDisconnectInput(BaseModel):
    """Body of ``disconnectLiveUser``: both ``liveUserId`` and ``message`` are required."""

    model_config = ConfigDict(extra="forbid")

    live_user_id: int = Field(
        ge=1,
        serialization_alias="liveUserId",
        description="Identifier of the live session to disconnect (integer >= 1).",
    )
    message: str = Field(
        min_length=1,
        max_length=600,
        description="Message shown to the disconnected user (1-600 characters).",
    )


# -- Outputs: bounded projections ------------------------------------------------------


class UserSummaryOutput(BaseModel):
    """One row of the general authentication-user list (``getUsers``).

    This is the contract's *basic summary*, not a network-user detail: it has no policies
    and no VPN access.
    """

    id: str = Field(description="Unique identifier (UUID).")
    name: str
    display_name: str
    description: str | None = None
    active: bool
    email_addresses: list[str] = Field(default_factory=list)
    group: str | None = Field(default=None, description="Primary group name, when returned.")
    additional_groups: list[str] = Field(default_factory=list)
    administrative_access: bool = Field(
        description="Whether this authentication user also has administrative access."
    )
    created_at: datetime | None = None
    updated_at: datetime | None = None


class NetworkUserPoliciesOutput(BaseModel):
    """Bounded projection of a network user's effective policies."""

    surfing_quota_policy: str | None = None
    access_time_policy: str | None = None
    network_traffic_quota_policy: str | None = None
    traffic_shaping_policy: str | None = None
    mac_binding: bool | None = None
    mac_addresses: list[str] = Field(default_factory=list)
    allowed_networks_any: bool | None = None
    allowed_networks_ipv4: list[str] = Field(default_factory=list)
    allowed_networks_ipv4_start: str | None = None
    allowed_networks_ipv4_end: str | None = None
    simultaneous_logins_use_global: bool | None = None
    simultaneous_logins_unlimited: bool | None = None
    simultaneous_logins_limit: int | None = None


class NetworkUserVpnAccessOutput(BaseModel):
    """Bounded projection of a network user's VPN-access overrides."""

    ssl_vpn_remote_access_policy: str | None = None
    ssl_vpn_clientless_policy: str | None = None
    ssl_vpn_static_ipv4_address: str | None = None
    ssl_vpn_static_ipv6_address: str | None = None
    l2tp: bool | None = None
    l2tp_static_ipv4_address: str | None = None
    pptp: bool | None = None
    pptp_static_ipv4_address: str | None = None
    ipsec_vpn_remote_access: bool | None = None
    ipsec_vpn_static_ipv4_address: str | None = None


class NetworkUserOutput(BaseModel):
    """One network-user account, without any credential material."""

    id: str = Field(description="Unique identifier (UUID).")
    name: str = Field(description="Unique login name.")
    display_name: str
    description: str | None = None
    active: bool
    email_addresses: list[str] = Field(default_factory=list)
    group: str | None = Field(default=None, description="Primary group name.")
    additional_groups: list[str] = Field(default_factory=list)
    policies: NetworkUserPoliciesOutput | None = None
    vpn_access: NetworkUserVpnAccessOutput | None = None
    email_quarantine_digest: bool | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class NetworkUserDeleteOutput(BaseModel):
    """Result of ``deleteNetworkUser``."""

    deleted: bool = Field(
        description=(
            "True when the appliance accepted the delete. The shared transport does not "
            "expose the response body of a DELETE, so this reflects the successful status."
        )
    )
    id_or_name: str = Field(description="Identifier the delete was issued for.")


class LiveUserSessionOutput(BaseModel):
    """One active user session (``getLiveUsers``)."""

    live_user_id: int = Field(description="Session identifier used by disconnectLiveUser.")
    user_name: str
    client_type: str = Field(
        description=(
            "Client type reported by the appliance; the documented vocabulary is "
            "LIVE_USER_CLIENT_TYPES."
        )
    )
    ipv4_address: str | None = None
    ipv6_address: str | None = None
    mac_address: str
    logged_in_time: datetime
    upload_data: int = Field(description="Bytes uploaded by the session.")
    download_data: int = Field(description="Bytes downloaded by the session.")
    transfer_rate: int = Field(description="Current transfer rate reported by the appliance.")
    duration: int = Field(description="Session duration reported by the appliance.")


class LiveUserDisconnectOutput(BaseModel):
    """Result of ``disconnectLiveUser``."""

    disconnected: bool = Field(description="True when the appliance disconnected the session.")
    live_user_id: int = Field(description="Session identifier the request was issued for.")


# -- Wire models: parse the appliance payload, never returned --------------------------


class _WireGroupRef(BaseModel):
    """``{name}`` reference used by network-user group memberships."""

    model_config = ConfigDict(extra="ignore")

    name: str


class _WirePolicyRef(BaseModel):
    """``{name}`` or ``{noPolicy: true}`` policy reference."""

    model_config = ConfigDict(extra="ignore")

    name: str | None = None
    noPolicy: bool | None = None  # noqa: N815 - the wire name is camelCase


class _WireAllowedNetworksIpv4(BaseModel):
    """``allowedNetworksIpv4`` oneOf, parsed leniently."""

    model_config = ConfigDict(extra="ignore")

    any: bool | None = None
    ipv4Addresses: list[str] = Field(default_factory=list)  # noqa: N815
    ipv4AddressStart: str | None = None  # noqa: N815
    ipv4AddressEnd: str | None = None  # noqa: N815


class _WireSimultaneousLogins(BaseModel):
    """``simultaneousLogins`` oneOf, parsed leniently."""

    model_config = ConfigDict(extra="ignore")

    useGlobalLimit: bool | None = None  # noqa: N815
    unlimited: bool | None = None
    limit: int | None = None


class NetworkUserPoliciesWire(BaseModel):
    """Policy block of a network-user payload."""

    model_config = ConfigDict(extra="ignore")

    surfingQuotaPolicy: _WirePolicyRef | None = None  # noqa: N815
    accessTimePolicy: _WirePolicyRef | None = None  # noqa: N815
    networkTrafficQuotaPolicy: _WirePolicyRef | None = None  # noqa: N815
    trafficShapingPolicy: _WirePolicyRef | None = None  # noqa: N815
    macBinding: bool | None = None  # noqa: N815
    macAddresses: list[str] = Field(default_factory=list)  # noqa: N815
    allowedNetworksIpv4: _WireAllowedNetworksIpv4 | None = None  # noqa: N815
    simultaneousLogins: _WireSimultaneousLogins | None = None  # noqa: N815


class NetworkUserVpnAccessWire(BaseModel):
    """VPN-access block of a network-user payload."""

    model_config = ConfigDict(extra="ignore")

    sslVpnRemoteAccessPolicy: _WirePolicyRef | None = None  # noqa: N815
    sslVpnClientlessPolicy: _WirePolicyRef | None = None  # noqa: N815
    sslVpnStaticIpv4Address: str | None = None  # noqa: N815
    sslVpnStaticIpv6Address: str | None = None  # noqa: N815
    l2tp: bool | None = None
    l2tpStaticIpv4Address: str | None = None  # noqa: N815
    pptp: bool | None = None
    pptpStaticIpv4Address: str | None = None  # noqa: N815
    ipsecVpnRemoteAccess: bool | None = None  # noqa: N815
    ipsecVpnStaticIpv4Address: str | None = None  # noqa: N815


class NetworkUserWire(BaseModel):
    """Network-user payload of ``getNetworkUser``/``createNetworkUser``/``updateNetworkUser``.

    Only the fields the output projection needs are declared; unknown members are ignored
    rather than echoed. There is deliberately no ``password`` member.
    """

    model_config = ConfigDict(extra="ignore")

    id: str
    name: str
    displayName: str  # noqa: N815
    description: str | None = None
    active: bool
    emailAddresses: list[str] = Field(default_factory=list)  # noqa: N815
    group: _WireGroupRef | None = None
    additionalGroups: list[_WireGroupRef] = Field(default_factory=list)  # noqa: N815
    policies: NetworkUserPoliciesWire | None = None
    vpnAccess: NetworkUserVpnAccessWire | None = None  # noqa: N815
    emailQuarantineDigest: bool | None = None  # noqa: N815
    createdAt: datetime | None = None  # noqa: N815
    updatedAt: datetime | None = None  # noqa: N815


class UserSummaryWire(BaseModel):
    """Basic-summary row of ``getUsers``."""

    model_config = ConfigDict(extra="ignore")

    id: str
    name: str
    displayName: str  # noqa: N815
    description: str | None = None
    active: bool
    emailAddresses: list[str] = Field(default_factory=list)  # noqa: N815
    group: _WireGroupRef | None = None
    additionalGroups: list[_WireGroupRef] = Field(default_factory=list)  # noqa: N815
    administrativeAccess: bool  # noqa: N815
    createdAt: datetime | None = None  # noqa: N815
    updatedAt: datetime | None = None  # noqa: N815


class LiveUserSessionWire(BaseModel):
    """One live-session row of ``getLiveUsers``."""

    model_config = ConfigDict(extra="ignore")

    liveUserId: int  # noqa: N815
    userName: str  # noqa: N815
    clientType: str  # noqa: N815
    ipv4Address: str | None = None  # noqa: N815
    ipv6Address: str | None = None  # noqa: N815
    macAddress: str  # noqa: N815
    loggedInTime: datetime  # noqa: N815
    uploadData: int  # noqa: N815
    downloadData: int  # noqa: N815
    transferRate: int  # noqa: N815
    duration: int


class DisconnectLiveUserWire(BaseModel):
    """Response body of ``disconnectLiveUser``."""

    model_config = ConfigDict(extra="ignore")

    disconnected: bool


# -- Projections -----------------------------------------------------------------------


def _policy_name(reference: _WirePolicyRef | None) -> str | None:
    """Return the referenced policy name, or ``None`` for an absent/``noPolicy`` reference."""
    return reference.name if reference is not None else None


def _project_policies(wire: NetworkUserPoliciesWire | None) -> NetworkUserPoliciesOutput | None:
    """Project the policy block into the bounded output model."""
    if wire is None:
        return None
    allowed = wire.allowedNetworksIpv4
    simultaneous = wire.simultaneousLogins
    return NetworkUserPoliciesOutput(
        surfing_quota_policy=_policy_name(wire.surfingQuotaPolicy),
        access_time_policy=_policy_name(wire.accessTimePolicy),
        network_traffic_quota_policy=_policy_name(wire.networkTrafficQuotaPolicy),
        traffic_shaping_policy=_policy_name(wire.trafficShapingPolicy),
        mac_binding=wire.macBinding,
        mac_addresses=list(wire.macAddresses),
        allowed_networks_any=allowed.any if allowed is not None else None,
        allowed_networks_ipv4=list(allowed.ipv4Addresses) if allowed is not None else [],
        allowed_networks_ipv4_start=allowed.ipv4AddressStart if allowed is not None else None,
        allowed_networks_ipv4_end=allowed.ipv4AddressEnd if allowed is not None else None,
        simultaneous_logins_use_global=(
            simultaneous.useGlobalLimit if simultaneous is not None else None
        ),
        simultaneous_logins_unlimited=(
            simultaneous.unlimited if simultaneous is not None else None
        ),
        simultaneous_logins_limit=simultaneous.limit if simultaneous is not None else None,
    )


def _project_vpn_access(
    wire: NetworkUserVpnAccessWire | None,
) -> NetworkUserVpnAccessOutput | None:
    """Project the VPN-access block into the bounded output model."""
    if wire is None:
        return None
    return NetworkUserVpnAccessOutput(
        ssl_vpn_remote_access_policy=_policy_name(wire.sslVpnRemoteAccessPolicy),
        ssl_vpn_clientless_policy=_policy_name(wire.sslVpnClientlessPolicy),
        ssl_vpn_static_ipv4_address=wire.sslVpnStaticIpv4Address,
        ssl_vpn_static_ipv6_address=wire.sslVpnStaticIpv6Address,
        l2tp=wire.l2tp,
        l2tp_static_ipv4_address=wire.l2tpStaticIpv4Address,
        pptp=wire.pptp,
        pptp_static_ipv4_address=wire.pptpStaticIpv4Address,
        ipsec_vpn_remote_access=wire.ipsecVpnRemoteAccess,
        ipsec_vpn_static_ipv4_address=wire.ipsecVpnStaticIpv4Address,
    )


def _project_network_user_wire(wire: NetworkUserWire) -> NetworkUserOutput:
    """Project one parsed network-user payload into the bounded MCP output model."""
    return NetworkUserOutput(
        id=wire.id,
        name=wire.name,
        display_name=wire.displayName,
        description=wire.description,
        active=wire.active,
        email_addresses=list(wire.emailAddresses),
        group=wire.group.name if wire.group is not None else None,
        additional_groups=[group.name for group in wire.additionalGroups],
        policies=_project_policies(wire.policies),
        vpn_access=_project_vpn_access(wire.vpnAccess),
        email_quarantine_digest=wire.emailQuarantineDigest,
        created_at=wire.createdAt,
        updated_at=wire.updatedAt,
    )


def project_network_user(payload: Mapping[str, Any]) -> NetworkUserOutput:
    """Project one network-user payload into the bounded MCP output model."""
    return _project_network_user_wire(NetworkUserWire.model_validate(payload))


def _project_user_summary(wire: UserSummaryWire) -> UserSummaryOutput:
    """Project one basic-summary row."""
    return UserSummaryOutput(
        id=wire.id,
        name=wire.name,
        display_name=wire.displayName,
        description=wire.description,
        active=wire.active,
        email_addresses=list(wire.emailAddresses),
        group=wire.group.name if wire.group is not None else None,
        additional_groups=[group.name for group in wire.additionalGroups],
        administrative_access=wire.administrativeAccess,
        created_at=wire.createdAt,
        updated_at=wire.updatedAt,
    )


def project_user_page(payload: Mapping[str, Any]) -> ListPage[UserSummaryOutput]:
    """Project one ``getUsers`` page, preserving the ``pages`` metadata exactly."""
    wire = ListPage[UserSummaryWire].model_validate(payload)
    return ListPage[UserSummaryOutput](
        items=[_project_user_summary(item) for item in wire.items],
        pages=wire.pages,
    )


def project_network_user_page(payload: Mapping[str, Any]) -> ListPage[NetworkUserOutput]:
    """Project one ``getNetworkUsers`` page, preserving the ``pages`` metadata exactly."""
    wire = ListPage[NetworkUserWire].model_validate(payload)
    return ListPage[NetworkUserOutput](
        items=[_project_network_user_wire(item) for item in wire.items],
        pages=wire.pages,
    )


def _project_live_user_session(wire: LiveUserSessionWire) -> LiveUserSessionOutput:
    """Project one live-session row."""
    return LiveUserSessionOutput(
        live_user_id=wire.liveUserId,
        user_name=wire.userName,
        client_type=wire.clientType,
        ipv4_address=wire.ipv4Address,
        ipv6_address=wire.ipv6Address,
        mac_address=wire.macAddress,
        logged_in_time=wire.loggedInTime,
        upload_data=wire.uploadData,
        download_data=wire.downloadData,
        transfer_rate=wire.transferRate,
        duration=wire.duration,
    )


def project_live_user_page(payload: Mapping[str, Any]) -> ListPage[LiveUserSessionOutput]:
    """Project the ``getLiveUsers`` ``{items, pages}`` body without inventing metadata."""
    wire = ListPage[LiveUserSessionWire].model_validate(payload)
    return ListPage[LiveUserSessionOutput](
        items=[_project_live_user_session(item) for item in wire.items],
        pages=wire.pages,
    )


def project_disconnect_live_user(
    payload: Mapping[str, Any], live_user_id: int
) -> LiveUserDisconnectOutput:
    """Project the ``disconnectLiveUser`` body and echo the targeted session id."""
    wire = DisconnectLiveUserWire.model_validate(payload)
    return LiveUserDisconnectOutput(disconnected=wire.disconnected, live_user_id=live_user_id)
