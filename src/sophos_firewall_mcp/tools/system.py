"""System information and status tools for Sophos Firewall."""

from typing import Any, Dict, List, Union, cast
from sophos_firewall_mcp.client import SophosFirewallClient, SophosResponseError


async def sophos_get_system_info(
    client: Any = None,
) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    """Retrieve system information including appliance model, firmware version, serial number, and uptime.

    Use when inspecting hardware/firmware details and overall system status.

    Args:
        client: Optional SophosFirewallClient instance.

    Returns:
        System information parameters from Sophos Firewall.
    """
    close_client = False
    if client is None:
        client = SophosFirewallClient()
        close_client = True

    try:
        res = await client.get_tag("SystemInformation")
        return cast(Union[Dict[str, Any], List[Dict[str, Any]]], res)
    except SophosResponseError as err:
        if getattr(err, "code", None) == "529" or "invalid" in str(err).lower():
            return {
                "Status": "Unsupported XML Module",
                "Message": (
                    "The SFOS XML API exposes no read-only module for appliance model, "
                    "serial number, firmware version or uptime. Modules rejected by the "
                    "appliance: SystemInformation, SystemInfo, System, SystemStatus, "
                    "Up2Date (all answer 529 'Input request module is Invalid'). Working "
                    "alternatives: sophos_get_service_status (SystemServices), "
                    "sophos_get_interface_list, or a raw Get on AdminSettings. For "
                    "firmware/uptime use SNMP or the appliance syslog stream."
                ),
                "Error": str(err),
            }
        raise
    finally:
        if close_client:
            await client.close()


async def sophos_get_service_status(
    client: Any = None,
) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    """Retrieve current operational status of system services (DNS, DHCP, IPS, Web Protection, AntiVirus).

    Reads the SFOS XML module ``SystemServices``, which reports the runtime state
    of each background service (RUNNING / Stop / UNREGISTERED). Service
    *definitions* live in a different module and are exposed by
    ``sophos_list_services``.

    Use when monitoring background service health or diagnosing firewall subsystem failures.

    Args:
        client: Optional SophosFirewallClient instance.

    Returns:
        Status details of core firewall services.
    """
    close_client = False
    if client is None:
        client = SophosFirewallClient()
        close_client = True

    try:
        res = await client.get_tag("SystemServices")
        return cast(Union[Dict[str, Any], List[Dict[str, Any]]], res)
    finally:
        if close_client:
            await client.close()


async def sophos_get_interface_list(
    client: Any = None,
) -> Union[Dict[str, Any], List[Dict[str, Any]]]:
    """List network interfaces with configuration, IP addresses, network zones, and link state.

    Use when inspecting physical or virtual interface configurations, subnets, and link states.

    Args:
        client: Optional SophosFirewallClient instance.

    Returns:
        List or dict of network interface configurations.
    """
    close_client = False
    if client is None:
        client = SophosFirewallClient()
        close_client = True

    try:
        res = await client.get_tag("Interface")
        return cast(Union[Dict[str, Any], List[Dict[str, Any]]], res)
    finally:
        if close_client:
            await client.close()
