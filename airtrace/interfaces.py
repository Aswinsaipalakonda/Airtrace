"""Interface discovery and hardware/driver diagnostic checks."""

import logging
from typing import Optional
from scapy.config import conf
from airtrace.models import InterfaceInfo

logger = logging.getLogger(__name__)

# Synthetic interface identifier used for demo/offline testing
DEMO_INTERFACE_ID = "__airtrace_synthetic_demo__"


def check_npcap_status() -> tuple[bool, str]:
    """
    Check if the Npcap packet capture driver is active and available to Scapy on Windows.
    Returns (is_available, message).
    """
    if conf.use_pcap:
        return True, "Npcap driver is active and ready for live capture."
    return False, (
        "Npcap driver is not detected on Windows. "
        "Live packet capture requires Npcap (https://npcap.com) with WinPcap-compatible mode. "
        "You can use 'Airtrace Synthetic Demo Adapter' to test all features immediately."
    )


def get_available_interfaces() -> list[InterfaceInfo]:
    """
    Enumerate network interfaces available on the system.
    Resolves human-friendly names, descriptions, IP addresses, and MAC addresses.
    Always includes the Synthetic Demo interface.
    """
    interfaces: list[InterfaceInfo] = []

    # Always prepend the Synthetic Demo Adapter for offline testing and immediate evaluation
    interfaces.append(
        InterfaceInfo(
            name="Airtrace Synthetic Demo Adapter",
            description="Virtual simulation adapter generating realistic IPv4 traffic for testing",
            device_id=DEMO_INTERFACE_ID,
            ip_address="192.168.1.100",
            mac_address="00:11:22:33:44:55",
            is_loopback=False,
        )
    )

    try:
        from scapy.arch.windows import get_windows_if_list
        win_ifs = get_windows_if_list()

        for item in win_ifs:
            friendly_name = item.get("name") or "Unknown Adapter"
            description = item.get("description") or friendly_name
            guid = item.get("guid") or ""
            ips = item.get("ips") or []
            mac = item.get("mac") or ""

            # Filter for valid IPv4 address if present
            ipv4_addr = next((ip for ip in ips if "." in ip and not ip.startswith("127.")), None)
            is_loop = "loopback" in friendly_name.lower() or "loopback" in description.lower()

            # Construct clean device ID for Scapy
            # On Windows, Scapy binds either via GUID (\Device\NPF_{...}) or friendly name
            device_id = item.get("win_name") or (f"\\Device\\NPF_{guid}" if guid else friendly_name)

            interfaces.append(
                InterfaceInfo(
                    name=friendly_name,
                    description=description,
                    device_id=device_id,
                    ip_address=ipv4_addr,
                    mac_address=mac,
                    is_loopback=is_loop,
                )
            )
    except Exception as e:
        logger.warning(f"Error enumerating Windows interfaces via Scapy: {e}")

    # Fallback to Scapy conf.ifaces if get_windows_if_list was empty
    if len(interfaces) <= 1:
        try:
            for iface_name, iface_obj in conf.ifaces.items():
                interfaces.append(
                    InterfaceInfo(
                        name=getattr(iface_obj, "name", iface_name),
                        description=getattr(iface_obj, "description", iface_name),
                        device_id=iface_name,
                        ip_address=getattr(iface_obj, "ip", None),
                        mac_address=getattr(iface_obj, "mac", None),
                        is_loopback=False,
                    )
                )
        except Exception as e:
            logger.warning(f"Fallback interface enumeration failed: {e}")

    return interfaces
