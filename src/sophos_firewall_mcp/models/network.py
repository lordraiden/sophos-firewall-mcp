"""Pydantic models for the Sophos network-architecture and network-status domains.

This module is the typed contract for issue #31's network surface:

* **41 read-only projections** of the network architecture: interfaces, zones, routing
  gateways (IPv4/IPv6, WAN and custom), static unicast routes, SD-WAN routes, DHCP
  servers, DHCP leases, DHCP relays, DNS settings, DNS host entries, DNS request routes
  and static neighbors;
* **three VLAN-only interface mutations** -- the only writes in this domain;
* **two status projections**: DNS protection status and cellular WAN modem status.

Response models use the contract's wire names (camelCase) so every projection is auditable
against ``firewall_config_openapi.yaml``, and ``extra="ignore"`` keeps a server-side
addition from breaking a read. Request models are closed (``extra="forbid"``), use
snake_case Python names with the wire name as an alias, and validate the documented
constraints before any I/O. Nothing in this module performs I/O.

Deliberate narrowings of the VLAN write surface (reported to the Lead, never silent):

* ``pppoe`` IPv4 assignment is not exposed: it requires write-only credentials and is a
  WAN-link concern, not a VLAN one.
* ``delegated`` IPv6 assignment and the ``dhcp``/``delegated`` sub-objects are not exposed
  for the same reason.
* ``hardwareName``, ``description``, ``mtu``/``mss`` on create and MAC override are not
  exposed because the contract marks them "not applicable when type is vlan" (create) or
  they belong to bridge/LAG interfaces. ``mtu``/``mss`` are accepted on update, where the
  contract does not restrict them.
* ``secondaryAddresses`` (alias add/remove envelopes) are not exposed in v1.
"""

from __future__ import annotations

import re
from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Annotated, Generic, Literal, Self, TypeVar

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .common import ObjectName, ObjectNameOrId, ObjectRef

__all__ = [
    "ActivationCondition",
    "CellularModem",
    "CellularNetwork",
    "CellularSignal",
    "CellularStatus",
    "CellularWanStatus",
    "CustomGatewayIpv4",
    "CustomGatewayIpv6",
    "DhcpAddressPoolIpv4",
    "DhcpAddressPoolIpv6",
    "DhcpClientReservationIpv4",
    "DhcpClientReservationIpv6",
    "DhcpLeaseIpv4",
    "DhcpLeaseIpv6",
    "DhcpOption",
    "DhcpRelayIpv4",
    "DhcpRelayIpv6",
    "DhcpServerIpv4",
    "DhcpServerIpv6",
    "DnsHostEntry",
    "DnsHostEntryRecord",
    "DnsOverHttpsServer",
    "DnsOverHttpsSettings",
    "DnsProtectionSettings",
    "DnsProtectionStatus",
    "DnsRequestRoute",
    "DnsSettings",
    "DnsUnencryptedIpv4",
    "DnsUnencryptedIpv6",
    "DnsUnencryptedSettings",
    "GatewayIpv4",
    "GatewayIpv6",
    "HealthCheck",
    "HealthCheckHost",
    "HealthCheckRule",
    "InterfaceBridgeDetails",
    "InterfaceBridgeMember",
    "InterfaceDeleteOutput",
    "InterfaceIpv4",
    "InterfaceIpv6",
    "InterfaceLagDetails",
    "InterfaceLagMember",
    "InterfacePermittedVlan",
    "InterfaceSecondaryAddress",
    "InterfaceVlanDetails",
    "KeysetPage",
    "KeysetPages",
    "NetworkInterface",
    "NetworkInterfaceCreateVlanInput",
    "NetworkInterfaceDeleteVlanInput",
    "NetworkInterfaceUpdateVlanInput",
    "PageInput",
    "FilterInput",
    "FilteredPageInput",
    "SdwanApplicationSelector",
    "SdwanGatewayChoice",
    "SdwanGatewayPair",
    "SdwanInterfaceSelector",
    "SdwanLinkSelection",
    "SdwanNetworkSelector",
    "SdwanRoute",
    "SdwanServiceSelector",
    "SdwanUserSelector",
    "StaticNeighborIpv4",
    "StaticNeighborIpv6",
    "UnicastRouteIpv4",
    "UnicastRouteIpv6",
    "VlanIpv4Create",
    "VlanIpv4Update",
    "VlanIpv6Create",
    "VlanIpv6Update",
    "WanGatewayIpv4",
    "WanGatewayIpv6",
    "Zone",
    "ZoneService",
]

# -- Shared primitives -----------------------------------------------------------------

#: UUID form the contract uses for ``format: uuid`` values (the DHCP relay path parameter
#: is a UUID, not a name-or-id).
_UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

#: Zone names carry an extra pattern in the contract.
_ZONE_NAME_PATTERN = r"^[a-zA-Z1-9][a-zA-Z0-9_]*$"


#: Interface name (``maxLength: 58`` in the contract).
InterfaceName = Annotated[ObjectName, Field(min_length=1, max_length=58)]

#: Interface reference accepted by a path parameter (name or UUID, ``maxLength: 58``).
InterfaceRef = Annotated[ObjectNameOrId, Field(min_length=1, max_length=58)]

#: Zone name (``maxLength: 60``, restricted pattern).
ZoneName = Annotated[ObjectName, Field(min_length=1, max_length=60, pattern=_ZONE_NAME_PATTERN)]

#: Zone reference accepted by a path parameter (name or UUID, ``maxLength: 60``).
ZoneRef = Annotated[ObjectNameOrId, Field(min_length=1, max_length=60)]

#: Gateway name (``maxLength: 50``).
GatewayName = Annotated[ObjectName, Field(min_length=1, max_length=50)]

#: Gateway reference accepted by a path parameter (name or UUID, ``maxLength: 50``).
GatewayRef = Annotated[ObjectNameOrId, Field(min_length=1, max_length=50)]

#: Route/neighbor/DHCP-server/DNS-entry reference (``maxLength: 64``).
WideRef = Annotated[ObjectNameOrId, Field(min_length=1, max_length=64)]

#: SD-WAN route reference (``maxLength: 60``).
SdwanRef = Annotated[ObjectNameOrId, Field(min_length=1, max_length=60)]

#: DHCP relay identifier: the contract declares ``format: uuid`` for this path parameter.
UuidString = Annotated[str, Field(pattern=_UUID_PATTERN.pattern)]

InterfaceType = Literal["physical", "vlan", "bridge", "lag", "xfrm", "cellularWan"]
ZoneType = Literal["lan", "wan", "dmz", "local", "vpn", "discover"]
GatewayKind = Literal["wan", "custom"]
WanGatewayRole = Literal["active", "backup"]
ActivationCondition = Literal[
    "anyActiveGatewayFails",
    "allActiveGatewaysFail",
    "specificGatewayFails",
    "manuallyActivate",
]
WeightOnActivation = Literal["useConfiguredWeight", "inheritFromLastFailedGateway"]
FailbackScope = Literal["newConnections", "allConnections"]
HealthCheckProtocol = Literal["tcp", "ping"]
LogicalOperator = Literal["and", "or"]
DhcpOptionType = Literal[
    "boolean",
    "string",
    "oneByte",
    "twoByte",
    "fourByte",
    "oneByteArray",
    "twoByteArray",
    "fourByteArray",
    "ipv4Addr",
    "ipv4AddrArray",
    "ipv6Addr",
    "ipv6AddrArray",
    "fqdn",
]
DnsProtocol = Literal["unencryptedDns", "dnsOverHttps"]
DnsProtectionState = Literal[
    "active",
    "notConfigured",
    "notSubscribed",
    "requiresSophosCentralRegistration",
    "firewallNotRecognized",
]
CellularConnectionState = Literal["disconnected", "connecting", "connected"]
CellularNetworkType = Literal["2G", "3G", "4G(LTE)", "5G"]
CellularNetworkMode = Literal["automatic", "manual"]
EnabledState = Literal["enabled", "disabled"]


class _Output(BaseModel):
    """Base for response projections: unknown server fields are ignored, never echoed."""

    model_config = ConfigDict(extra="ignore")


class _Input(BaseModel):
    """Base for closed request models: the contract is closed, unknown fields are a bug."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


# -- Request models --------------------------------------------------------------------


class PageInput(_Input):
    """One page of a paginated collection.

    Only for the operations whose contract declares ``page``/``pageSize``/``pageTotal``.
    The bounds are validated here and again by the client before any I/O: the appliance
    accepts ``page=0`` and rejects ``pageSize`` above 100 with ``400 invalidPageSizeParam``.
    """

    page: int = Field(default=1, ge=1, description="1-based page number.")
    page_size: int = Field(
        default=50, ge=1, le=100, alias="pageSize", description="Page size, 1-100."
    )
    page_total: bool = Field(
        default=False,
        alias="pageTotal",
        description="Ask the appliance for pages.total and pages.items.",
    )


class FilteredPageInput(PageInput):
    """A page plus the ``nameContains``/``nameNotEquals`` filters the contract declares."""

    name_contains: str | None = Field(
        default=None,
        alias="nameContains",
        min_length=1,
        max_length=255,
        description="Only return objects whose name contains this text.",
    )
    name_not_equals: str | None = Field(
        default=None,
        alias="nameNotEquals",
        min_length=1,
        max_length=255,
        description="Exclude the object with exactly this name.",
    )

    def name_filters(self) -> dict[str, str]:
        """The declared name filters, omitting the ones the caller did not set."""
        filters: dict[str, str] = {}
        if self.name_contains is not None:
            filters["nameContains"] = self.name_contains
        if self.name_not_equals is not None:
            filters["nameNotEquals"] = self.name_not_equals
        return filters


class FilterInput(_Input):
    """Name filters for an unpaginated collection (DHCP servers and relays)."""

    name_contains: str | None = Field(
        default=None,
        alias="nameContains",
        min_length=1,
        max_length=255,
        description="Only return objects whose name contains this text.",
    )
    name_not_equals: str | None = Field(
        default=None,
        alias="nameNotEquals",
        min_length=1,
        max_length=255,
        description="Exclude the object with exactly this name.",
    )

    def name_filters(self) -> dict[str, str]:
        """The declared name filters, omitting the ones the caller did not set."""
        filters: dict[str, str] = {}
        if self.name_contains is not None:
            filters["nameContains"] = self.name_contains
        if self.name_not_equals is not None:
            filters["nameNotEquals"] = self.name_not_equals
        return filters


class InterfaceRefInput(_Input):
    """Identify one interface by name or UUID."""

    id_or_name: InterfaceRef = Field(alias="idOrName", description="Interface name or UUID.")


class ZoneRefInput(_Input):
    """Identify one zone by name or UUID."""

    id_or_name: ZoneRef = Field(alias="idOrName", description="Zone name or UUID.")


class GatewayRefInput(_Input):
    """Identify one gateway by name or UUID."""

    id_or_name: GatewayRef = Field(alias="idOrName", description="Gateway name or UUID.")


class WideRefInput(_Input):
    """Identify one route, DHCP server, DNS entry or static neighbor by name or UUID."""

    id_or_name: WideRef = Field(
        alias="idOrName", description="Object name or UUID (at most 64 characters)."
    )


class SdwanRefInput(_Input):
    """Identify one SD-WAN route by name or UUID."""

    id_or_name: SdwanRef = Field(alias="idOrName", description="SD-WAN route name or UUID.")


class DhcpRelayRefInput(_Input):
    """Identify one DHCP relay by UUID.

    The contract declares ``format: uuid`` for this path parameter, so a relay name is
    rejected before any I/O.
    """

    id: UuidString = Field(description="DHCP relay UUID.")


class VlanIpv4Create(_Input):
    """IPv4 settings of a new VLAN interface (``ipv4`` member of the create body)."""

    assignment_type: Literal["static", "dhcp"] = Field(
        alias="assignmentType", description="IPv4 assignment type."
    )
    ipv4_address: IPv4Address | None = Field(
        default=None, alias="ipv4Address", description="Required when assignmentType is static."
    )
    cidr: int | None = Field(
        default=None, ge=1, le=32, description="Prefix length; required for a static address."
    )
    gateway_name: GatewayName | None = Field(
        default=None, alias="gatewayName", description="Name of the gateway object."
    )
    gateway_ip_address: IPv4Address | None = Field(
        default=None,
        alias="gatewayIpAddress",
        description="Gateway address; only applicable to a static assignment.",
    )

    @model_validator(mode="after")
    def _check_static_fields(self) -> Self:
        if self.assignment_type == "static":
            if self.ipv4_address is None or self.cidr is None:
                raise ValueError(
                    "ipv4Address and cidr are required when assignmentType is 'static'"
                )
        elif self.ipv4_address is not None or self.cidr is not None:
            raise ValueError(
                "ipv4Address and cidr are only applicable when assignmentType is 'static'"
            )
        return self


class VlanIpv4Update(_Input):
    """IPv4 settings of an existing VLAN interface (``ipv4`` member of the PATCH body)."""

    assignment_type: Literal["static", "dhcp"] | None = Field(
        default=None, alias="assignmentType", description="IPv4 assignment type."
    )
    ipv4_address: IPv4Address | None = Field(
        default=None, alias="ipv4Address", description="Only applicable to a static assignment."
    )
    cidr: int | None = Field(default=None, ge=1, le=32, description="Static prefix length.")
    gateway_name: GatewayName | None = Field(
        default=None, alias="gatewayName", description="Name of the gateway object."
    )
    gateway_ip_address: IPv4Address | None = Field(
        default=None, alias="gatewayIpAddress", description="Static gateway address."
    )

    @model_validator(mode="after")
    def _check_static_fields(self) -> Self:
        if self.assignment_type == "static" and (self.ipv4_address is None or self.cidr is None):
            raise ValueError("ipv4Address and cidr are required when assignmentType is 'static'")
        return self


class VlanIpv6Create(_Input):
    """IPv6 settings of a new VLAN interface (``ipv6`` member of the create body)."""

    assignment_type: Literal["static", "dhcp"] = Field(
        alias="assignmentType", description="IPv6 assignment type."
    )
    ipv6_address: IPv6Address | None = Field(
        default=None, alias="ipv6Address", description="Required when assignmentType is static."
    )
    prefix_length: int | None = Field(
        default=None, alias="prefixLength", ge=1, le=128, description="Static prefix length."
    )
    gateway_name: GatewayName | None = Field(
        default=None, alias="gatewayName", description="Name of the gateway object."
    )
    gateway_ip_address: IPv6Address | None = Field(
        default=None, alias="gatewayIpAddress", description="Static gateway address."
    )

    @model_validator(mode="after")
    def _check_static_fields(self) -> Self:
        if self.assignment_type == "static":
            if self.ipv6_address is None or self.prefix_length is None:
                raise ValueError(
                    "ipv6Address and prefixLength are required when assignmentType is 'static'"
                )
        elif self.ipv6_address is not None or self.prefix_length is not None:
            raise ValueError(
                "ipv6Address and prefixLength are only applicable when assignmentType is 'static'"
            )
        return self


class VlanIpv6Update(_Input):
    """IPv6 settings of an existing VLAN interface (``ipv6`` member of the PATCH body)."""

    assignment_type: Literal["static", "dhcp"] | None = Field(
        default=None, alias="assignmentType", description="IPv6 assignment type."
    )
    ipv6_address: IPv6Address | None = Field(
        default=None, alias="ipv6Address", description="Only applicable to a static assignment."
    )
    prefix_length: int | None = Field(
        default=None, alias="prefixLength", ge=1, le=128, description="Static prefix length."
    )
    gateway_name: GatewayName | None = Field(
        default=None, alias="gatewayName", description="Name of the gateway object."
    )
    gateway_ip_address: IPv6Address | None = Field(
        default=None, alias="gatewayIpAddress", description="Static gateway address."
    )

    @model_validator(mode="after")
    def _check_static_fields(self) -> Self:
        if self.assignment_type == "static" and (
            self.ipv6_address is None or self.prefix_length is None
        ):
            raise ValueError(
                "ipv6Address and prefixLength are required when assignmentType is 'static'"
            )
        return self


class NetworkInterfaceCreateVlanInput(_Input):
    """Create one VLAN interface.

    The tool always sends ``type: "vlan"``: the contract's create body also accepts
    ``bridge`` and ``lag``, and those are deliberately not reachable from this server.
    ``hardwareName``, ``description``, ``mtu``/``mss`` and the MAC override are not
    accepted because the contract marks them "not applicable when type is vlan".
    """

    name: InterfaceName = Field(description="Name of the new VLAN interface.")
    vlan_id: int = Field(ge=1, le=4094, alias="vlanId", description="VLAN ID (1-4094).")
    parent_interface: InterfaceName = Field(
        alias="parentInterface",
        description=(
            "Existing interface the VLAN is created on. It is read first with "
            "getNetworkInterface: it must exist and must be a physical, vlan, bridge or "
            "lag interface."
        ),
    )
    zone: ZoneName | None = Field(default=None, description="Zone the VLAN belongs to.")
    ipv4: VlanIpv4Create | None = Field(default=None, description="Optional IPv4 settings.")
    ipv6: VlanIpv6Create | None = Field(default=None, description="Optional IPv6 settings.")


class NetworkInterfaceUpdateVlanInput(_Input):
    """Update one VLAN interface with a JSON Merge Patch body.

    Only fields the caller sets are sent. The contract's PATCH body has no
    ``vlanDetails`` member, so the VLAN ID and parent interface cannot be changed; it also
    marks ``description`` as bridge-only, so it is not exposed here.
    """

    id_or_name: InterfaceRef = Field(
        alias="idOrName", description="VLAN interface to update (name or UUID)."
    )
    name: InterfaceName | None = Field(default=None, description="New name of the interface.")
    zone: ZoneName | None = Field(default=None, description="Zone the VLAN belongs to.")
    ipv4: VlanIpv4Update | None = Field(default=None, description="IPv4 settings to change.")
    ipv6: VlanIpv6Update | None = Field(default=None, description="IPv6 settings to change.")
    mtu: int | None = Field(default=None, ge=576, le=9000, description="Maximum transmission unit.")
    mss: int | None = Field(default=None, ge=536, le=8960, description="Maximum segment size.")

    @model_validator(mode="after")
    def _require_a_change(self) -> Self:
        if not any(
            value is not None
            for value in (self.name, self.zone, self.ipv4, self.ipv6, self.mtu, self.mss)
        ):
            raise ValueError("at least one field must be provided for a partial update")
        return self


class NetworkInterfaceDeleteVlanInput(_Input):
    """Delete one VLAN interface.

    ``deleteNetworkInterface`` has no request body, so the pre-read of the interface type
    is the only enforcement of the VLAN-only rule.
    """

    id_or_name: InterfaceRef = Field(alias="idOrName", description="VLAN interface name or UUID.")


# -- Interfaces ------------------------------------------------------------------------


class InterfaceVlanDetails(_Output):
    """VLAN-specific settings of an interface."""

    vlanId: int | None = None
    parentInterface: ObjectRef | None = None


class InterfaceBridgeMember(_Output):
    """One bridge member interface and its zone."""

    interface: ObjectRef | None = None
    zone: ObjectRef | None = None


class InterfacePermittedVlan(_Output):
    """A single permitted VLAN ID or a permitted VLAN ID range."""

    vlanId: int | None = None
    startVlanId: int | None = None
    endVlanId: int | None = None


class InterfaceBridgeDetails(_Output):
    """Bridge-specific settings of an interface."""

    members: list[InterfaceBridgeMember] = Field(default_factory=list)
    routing: bool | None = None
    filterVlans: bool | None = None
    permittedVlans: list[InterfacePermittedVlan] = Field(default_factory=list)
    permitArpBroadcast: bool | None = None
    stp: bool | None = None
    stpMaxAge: int | None = None
    macAging: int | None = None
    filterEthernetFrames: bool | None = None
    allowedEtherTypes: list[str] = Field(default_factory=list)


class InterfaceLagMember(_Output):
    """One LAG member interface."""

    interface: ObjectRef | None = None


class InterfaceLagDetails(_Output):
    """LAG-specific settings of an interface."""

    members: list[InterfaceLagMember] = Field(default_factory=list)
    primaryInterface: ObjectRef | None = None
    mode: Literal["activeBackup", "lacp8023ad"] | None = None
    loadBalanceMethod: Literal["layer2", "layer2And3", "layer3And4"] | None = None


class InterfaceSecondaryAddress(_Output):
    """A secondary (alias) address of an interface."""

    ipv4Address: str | None = None
    ipv6Address: str | None = None
    cidr: int | None = None
    prefixLength: int | None = None


class InterfaceIpv4(_Output):
    """IPv4 configuration of an interface."""

    assignmentType: Literal["static", "pppoe", "dhcp", "cellularWan"] | None = None
    ipv4Address: str | None = None
    cidr: int | None = None
    gatewayName: str | None = None
    gatewayIpAddress: str | None = None
    secondaryAddresses: list[InterfaceSecondaryAddress] = Field(default_factory=list)


class InterfaceIpv6(_Output):
    """IPv6 configuration of an interface."""

    assignmentType: Literal["static", "dhcp", "delegated"] | None = None
    ipv6Address: str | None = None
    prefixLength: int | None = None
    gatewayName: str | None = None
    gatewayIpAddress: str | None = None
    secondaryAddresses: list[InterfaceSecondaryAddress] = Field(default_factory=list)


class NetworkInterface(_Output):
    """One network interface, projected from the contract's interface object.

    ``type`` is the field the VLAN tools rely on: only ``vlan`` interfaces may be written.
    """

    id: str | None = None
    name: str | None = None
    hardwareName: str | None = None
    description: str | None = None
    enabled: bool | None = None
    type: InterfaceType | None = None
    vlanDetails: InterfaceVlanDetails | None = None
    bridgeDetails: InterfaceBridgeDetails | None = None
    lagDetails: InterfaceLagDetails | None = None
    memberOf: str | None = None
    zone: ObjectRef | None = None
    ipv4: InterfaceIpv4 | None = None
    ipv6: InterfaceIpv6 | None = None
    mtu: int | None = None
    mss: int | None = None
    overrideMac: bool | None = None
    macAddress: str | None = None
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


class InterfaceDeleteOutput(_Output):
    """Result of ``deleteNetworkInterface``."""

    deleted: bool


# -- Zones -----------------------------------------------------------------------------


class ZoneService(_Output):
    """One firewall service allowed for a zone.

    ``name`` is carried as a string rather than a ``Literal``: the contract declares a
    20-value catalog, and a read must not fail if a firmware build adds a service.
    """

    name: str | None = None


class Zone(_Output):
    """One network zone."""

    id: str | None = None
    name: str | None = None
    type: ZoneType | None = None
    description: str | None = None
    services: list[ZoneService] = Field(default_factory=list)
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


# -- Routing gateways ------------------------------------------------------------------


class GatewayIpv4(_Output):
    """One IPv4 gateway from the combined WAN/custom collection."""

    id: str | None = None
    name: str | None = None
    type: GatewayKind | None = None
    interface: ObjectRef | None = None
    ipv4Address: str | None = None
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


class GatewayIpv6(_Output):
    """One IPv6 gateway from the combined WAN/custom collection."""

    id: str | None = None
    name: str | None = None
    type: GatewayKind | None = None
    interface: ObjectRef | None = None
    ipv6Address: str | None = None
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


class HealthCheckHost(_Output):
    """Monitored host of a gateway health check: an IPv4 address, an IPv6 address or an FQDN."""

    ipv4Address: str | None = None
    ipv6Address: str | None = None
    fqdn: str | None = None


class HealthCheckRule(_Output):
    """One gateway health-check monitoring rule."""

    protocol: HealthCheckProtocol | None = None
    port: int | None = None
    logicalOperator: LogicalOperator | None = None
    host: HealthCheckHost | None = None


class HealthCheck(_Output):
    """Gateway health-check settings."""

    enabled: bool | None = None
    intervalBetweenChecks: int | None = None
    responseTimeout: int | None = None
    retries: int | None = None
    rules: list[HealthCheckRule] = Field(default_factory=list)


class BackupGatewaySettings(_Output):
    """Activation settings of a backup WAN gateway."""

    activationCondition: ActivationCondition | None = None
    gateway: ObjectRef | None = None
    weightOnActivation: WeightOnActivation | None = None
    failbackScope: FailbackScope | None = None


class WanGatewayIpv4(_Output):
    """One IPv4 WAN gateway."""

    id: str | None = None
    name: str | None = None
    type: WanGatewayRole | None = None
    weight: int | None = None
    interface: ObjectRef | None = None
    ipv4Address: str | None = None
    backupGatewaySettings: BackupGatewaySettings | None = None
    healthCheck: HealthCheck | None = None
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


class WanGatewayIpv6(_Output):
    """One IPv6 WAN gateway."""

    id: str | None = None
    name: str | None = None
    type: WanGatewayRole | None = None
    weight: int | None = None
    interface: ObjectRef | None = None
    ipv6Address: str | None = None
    backupGatewaySettings: BackupGatewaySettings | None = None
    healthCheck: HealthCheck | None = None
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


class CustomGatewayIpv4(_Output):
    """One custom IPv4 gateway."""

    id: str | None = None
    name: str | None = None
    interface: ObjectRef | None = None
    zone: ObjectRef | None = None
    ipv4Address: str | None = None
    healthCheck: HealthCheck | None = None
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


class CustomGatewayIpv6(_Output):
    """One custom IPv6 gateway."""

    id: str | None = None
    name: str | None = None
    interface: ObjectRef | None = None
    zone: ObjectRef | None = None
    ipv6Address: str | None = None
    healthCheck: HealthCheck | None = None
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


# -- Static unicast routes -------------------------------------------------------------


class UnicastRouteIpv4(_Output):
    """One static IPv4 unicast route (configuration, not the live routing table)."""

    name: str | None = None
    id: str | None = None
    destinationAddressIpv4: str | None = None
    cidr: int | None = None
    gatewayIpv4: str | None = None
    interface: ObjectRef | None = None
    metric: int | None = None
    administrativeDistance: int | None = None
    description: str | None = None
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


class UnicastRouteIpv6(_Output):
    """One static IPv6 unicast route (configuration, not the live routing table)."""

    name: str | None = None
    id: str | None = None
    destinationAddressIpv6: str | None = None
    prefixLength: int | None = None
    gatewayIpv6: str | None = None
    interface: ObjectRef | None = None
    metric: int | None = None
    description: str | None = None
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


# -- SD-WAN routes ---------------------------------------------------------------------


class SdwanInterfaceSelector(_Output):
    """Inbound-interface selector of an SD-WAN route: ``any`` or one named interface."""

    any: bool | None = None
    name: str | None = None


class SdwanServiceSelector(_Output):
    """Service selector of an SD-WAN route: ``any`` or explicit services and groups."""

    any: bool | None = None
    services: list[ObjectRef] = Field(default_factory=list)
    serviceGroups: list[ObjectRef] = Field(default_factory=list)


class SdwanApplicationSelector(_Output):
    """Application selector of an SD-WAN route: ``any`` or explicit application objects."""

    any: bool | None = None
    objects: list[ObjectRef] = Field(default_factory=list)


class SdwanUserSelector(_Output):
    """User selector of an SD-WAN route: ``any`` or explicit users and groups."""

    any: bool | None = None
    users: list[ObjectRef] = Field(default_factory=list)
    userGroups: list[ObjectRef] = Field(default_factory=list)


class SdwanGatewayChoice(_Output):
    """A primary or backup gateway choice: WAN link load balancing or a named gateway."""

    wanLinkLoadBalance: bool | None = None
    name: str | None = None


class SdwanGatewayPair(_Output):
    """Primary and optional backup gateway of an SD-WAN route."""

    primaryGateway: SdwanGatewayChoice | None = None
    backupGateway: SdwanGatewayChoice | None = None


class SdwanLinkSelection(_Output):
    """Link selection of an SD-WAN route: an SD-WAN profile or explicit gateways."""

    sdwanProfile: ObjectRef | None = None
    gateway: SdwanGatewayPair | None = None
    routeThroughSpecificGateway: bool | None = None


class SdwanNetworkSelector(_Output):
    """Source or destination network selector of an SD-WAN route.

    The IPv4 and IPv6 members are both modelled: the contract uses the same selector shape
    for both address families and only the populated family is returned.
    """

    any: bool | None = None
    macAddresses: list[ObjectRef] = Field(default_factory=list)
    ipv4Addresses: list[ObjectRef] = Field(default_factory=list)
    ipv4Groups: list[ObjectRef] = Field(default_factory=list)
    ipv6Addresses: list[ObjectRef] = Field(default_factory=list)
    ipv6Groups: list[ObjectRef] = Field(default_factory=list)
    fqdnAddresses: list[ObjectRef] = Field(default_factory=list)
    fqdnGroups: list[ObjectRef] = Field(default_factory=list)
    countries: list[ObjectRef] = Field(default_factory=list)
    countryGroups: list[ObjectRef] = Field(default_factory=list)


class SdwanRoute(_Output):
    """One SD-WAN route (IPv4 and IPv6 share this projection; configuration, not live state).

    ``dscpMarking`` is carried as a string rather than a ``Literal``: the contract declares
    a 64-value catalog, and a read must not fail if a firmware build adds a value.
    """

    id: str | None = None
    name: str | None = None
    description: str | None = None
    inboundInterface: SdwanInterfaceSelector | None = None
    servicesOrGroups: SdwanServiceSelector | None = None
    applications: SdwanApplicationSelector | None = None
    usersOrGroups: SdwanUserSelector | None = None
    dscpMarking: str | None = None
    linkSelection: SdwanLinkSelection | None = None
    enabled: bool | None = None
    sourceNetworks: SdwanNetworkSelector | None = None
    destinationNetworks: SdwanNetworkSelector | None = None
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


# -- DHCP ------------------------------------------------------------------------------


class DhcpAddressPoolIpv4(_Output):
    """One IPv4 DHCP address pool."""

    startAddressIpv4: str | None = None
    endAddressIpv4: str | None = None


class DhcpAddressPoolIpv6(_Output):
    """One IPv6 DHCP address pool."""

    startAddressIpv6: str | None = None
    endAddressIpv6: str | None = None


class DhcpClientReservationIpv4(_Output):
    """One IPv4 DHCP client reservation."""

    hostname: str | None = None
    macAddress: str | None = None
    ipv4Address: str | None = None


class DhcpClientReservationIpv6(_Output):
    """One IPv6 DHCP client reservation."""

    hostname: str | None = None
    duid: str | None = None
    ipv6Address: str | None = None


class DhcpOption(_Output):
    """One DHCP option served by a DHCP server."""

    option: str | None = None
    code: int | None = None
    type: DhcpOptionType | None = None
    value: str | None = None


class DhcpServerIpv4(_Output):
    """One IPv4 DHCP server (configuration, not live leases)."""

    id: str | None = None
    name: str | None = None
    enabled: bool | None = None
    interface: ObjectRef | None = None
    acceptRelayRequests: bool | None = None
    addressPools: list[DhcpAddressPoolIpv4] = Field(default_factory=list)
    clientReservations: list[DhcpClientReservationIpv4] = Field(default_factory=list)
    cidr: int | None = None
    domainName: str | None = None
    gatewayIpv4: str | None = None
    maxLifetime: int | None = None
    defaultLifetime: int | None = None
    conflictDetection: bool | None = None
    primaryDnsIpv4: str | None = None
    secondaryDnsIpv4: str | None = None
    primaryWins: str | None = None
    secondaryWins: str | None = None
    bootFile: str | None = None
    dhcpOptions: list[DhcpOption] = Field(default_factory=list)
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


class DhcpServerIpv6(_Output):
    """One IPv6 DHCP server (configuration, not live leases)."""

    id: str | None = None
    name: str | None = None
    enabled: bool | None = None
    interface: ObjectRef | None = None
    acceptRelayRequests: bool | None = None
    addressPools: list[DhcpAddressPoolIpv6] = Field(default_factory=list)
    clientReservations: list[DhcpClientReservationIpv6] = Field(default_factory=list)
    preferredLifetime: int | None = None
    defaultLifetime: int | None = None
    primaryDnsIpv6: str | None = None
    secondaryDnsIpv6: str | None = None
    dhcpOptions: list[DhcpOption] = Field(default_factory=list)
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


class DhcpLeaseIpv4(_Output):
    """One active IPv4 DHCP lease (live state)."""

    leasedStart: datetime | None = None
    leasedEnd: datetime | None = None
    leasedIp: str | None = None
    macAddress: str | None = None
    clientHostName: str | None = None
    leaseType: Literal["static", "dynamic"] | None = None


class DhcpLeaseIpv6(_Output):
    """One active IPv6 DHCP lease (live state)."""

    leasedStart: datetime | None = None
    leasedEnd: datetime | None = None
    leasedIp: str | None = None
    macAddress: str | None = None
    duid: str | None = None


class KeysetPages(_Output):
    """Keyset pagination metadata of the DHCP lease collections.

    The contract returns ``fromKey``/``nextKey`` instead of ``current``: the lease
    endpoints declare no ``page``/``pageSize`` request parameters, so the keys are
    preserved as metadata only and no pagination input is exposed.
    """

    fromKey: str | None = None
    nextKey: str | None = None
    total: int | None = None
    items: int | None = None
    size: int | None = None
    maxSize: int | None = None


ItemT = TypeVar("ItemT")


class KeysetPage(BaseModel, Generic[ItemT]):
    """One page of a keyset-paginated Sophos collection (DHCP leases)."""

    model_config = ConfigDict(extra="ignore")

    items: list[ItemT]
    pages: KeysetPages | None = None


class DhcpRelayIpv4(_Output):
    """One IPv4 DHCP relay."""

    id: str | None = None
    name: str | None = None
    interface: ObjectRef | None = None
    dhcpServerAddressesIpv4: list[str] = Field(default_factory=list)
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


class DhcpRelayIpv6(_Output):
    """One IPv6 DHCP relay."""

    id: str | None = None
    name: str | None = None
    interface: ObjectRef | None = None
    dhcpServerAddressesIpv6: list[str] = Field(default_factory=list)
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


# -- DNS -------------------------------------------------------------------------------


class DnsProtectionSettings(_Output):
    """DNS Protection settings inside the DNS settings object."""

    enabled: bool | None = None
    fallback: bool | None = None


class DnsUnencryptedIpv4(_Output):
    """Unencrypted DNS IPv4 upstream settings."""

    upstreamResolutionMethod: Literal["static", "dhcp", "pppoe"] | None = None
    dnsServer1: str | None = None
    dnsServer2: str | None = None
    dnsServer3: str | None = None


class DnsUnencryptedIpv6(_Output):
    """Unencrypted DNS IPv6 upstream settings."""

    upstreamResolutionMethod: Literal["static", "dhcp"] | None = None
    dnsServer1: str | None = None
    dnsServer2: str | None = None
    dnsServer3: str | None = None


class DnsUnencryptedSettings(_Output):
    """Unencrypted DNS settings."""

    ipv4: DnsUnencryptedIpv4 | None = None
    ipv6: DnsUnencryptedIpv6 | None = None


class DnsOverHttpsServer(_Output):
    """One DNS-over-HTTPS server: a URL plus the address family it resolves over."""

    url: str | None = None
    ipv4Address: str | None = None
    ipv6Address: str | None = None


class DnsOverHttpsSettings(_Output):
    """DNS-over-HTTPS settings."""

    dnsServer1: DnsOverHttpsServer | None = None
    dnsServer2: DnsOverHttpsServer | None = None
    dnsServer3: DnsOverHttpsServer | None = None
    fallbackToUnencryptedDns: bool | None = None


class DnsSettings(_Output):
    """The firewall's DNS settings (configuration, not the live resolver state)."""

    dnsProtection: DnsProtectionSettings | None = None
    dnsSecProtection: bool | None = None
    dnsProtocol: DnsProtocol | None = None
    unencryptedDns: DnsUnencryptedSettings | None = None
    dnsOverHttps: DnsOverHttpsSettings | None = None
    updatedAt: datetime | None = None


class DnsHostEntryRecord(_Output):
    """One record of a DNS host entry: an IPv4 or an IPv6 address/interface."""

    ttl: int | None = None
    weight: int | None = None
    publishOnWan: bool | None = None
    ipv4Address: str | None = None
    ipv4Interface: ObjectRef | None = None
    ipv6Address: str | None = None
    ipv6Interface: ObjectRef | None = None


class DnsHostEntry(_Output):
    """One DNS host entry."""

    id: str | None = None
    name: str | None = None
    domain: str | None = None
    enableReverseResolution: bool | None = None
    hostEntries: list[DnsHostEntryRecord] = Field(default_factory=list)
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


class DnsRequestRoute(_Output):
    """One DNS request route: a domain forwarded to a set of DNS servers."""

    id: str | None = None
    name: str | None = None
    domain: str | None = None
    dnsServers: list[ObjectRef] = Field(default_factory=list)
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


# -- Static neighbors ------------------------------------------------------------------


class StaticNeighborIpv4(_Output):
    """One static IPv4 neighbor entry."""

    id: str | None = None
    name: str | None = None
    ipv4Address: str | None = None
    macAddress: str | None = None
    interface: ObjectRef | None = None
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


class StaticNeighborIpv6(_Output):
    """One static IPv6 neighbor entry."""

    id: str | None = None
    name: str | None = None
    ipv6Address: str | None = None
    macAddress: str | None = None
    interface: ObjectRef | None = None
    createdAt: datetime | None = None
    updatedAt: datetime | None = None


# -- Network status --------------------------------------------------------------------


class DnsProtectionStatus(_Output):
    """DNS Protection status as reported by the appliance."""

    status: DnsProtectionState
    updatedAt: datetime | None = None


class CellularStatus(_Output):
    """Connection and SIM status of a cellular modem."""

    connection: CellularConnectionState | None = None
    sim: str | None = None


class CellularSignal(_Output):
    """Cellular signal-strength indicators."""

    rssi: str | None = None
    rsrq: str | None = None
    rsrp: str | None = None
    snr: str | None = None


class CellularNetwork(_Output):
    """Cellular network registration details."""

    mode: CellularNetworkMode | None = None
    dataRoaming: EnabledState | None = None
    registered: bool | None = None
    type: CellularNetworkType | None = None
    operator: str | None = None


class CellularModem(_Output):
    """One cellular WAN modem and its live state."""

    model: str | None = None
    status: CellularStatus | None = None
    signal: CellularSignal | None = None
    airplaneMode: EnabledState | None = None
    cellularNetwork: CellularNetwork | None = None
    uploadKbps: int | None = None
    downloadKbps: int | None = None
    connectionDuration: str | None = None


class CellularWanStatus(_Output):
    """Cellular WAN modem status as reported by the appliance.

    This is live modem state, not configuration, and it is not a general firewall health
    check: the contract exposes no such endpoint.
    """

    noOfModemsDetected: int
    modem: CellularModem | None = None
