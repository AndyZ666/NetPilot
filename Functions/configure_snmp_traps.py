#!/usr/bin/env python3
"""
SNMP Trap Configuration Deployment and Audit Tool

Deploys and audits SNMP trap configuration across Arista cEOS network devices.
Supports audit-only mode (default) and configuration application mode (--apply).

Safety: Non-destructive by default, idempotent when applying changes.
"""

import json
import subprocess
import sys
import argparse
import re
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from pathlib import Path


# ============================================================================
# CONFIGURATION CONSTANTS
# ============================================================================

NMAS_TRAP_RECEIVER = "172.20.20.1"
TRAP_UDP_PORT = 162
SNMP_VERSION = "2c"  # Note: This is for the config command (not v2c)
SNMP_COMMUNITY = "NetPilot"
SOURCE_INTERFACE = "Management0"

REQUIRED_DEVICES = {"R1", "R2", "R3", "R4", "R5", "S1", "S2", "S3", "S4"}
EXPECTED_DEVICE_COUNT = 9

# Timeout for subprocess commands
COMMAND_TIMEOUT = 10


# ============================================================================
# DATACLASSES
# ============================================================================

@dataclass
class Device:
    """Represents a network device from inventory."""
    name: str
    ip: str
    device_type: str
    role: str
    container_name: str


@dataclass
class AuditResult:
    """Represents the audit result for a single device."""
    device: Device
    container_running: bool = False
    trap_host: Optional[str] = None
    trap_port: Optional[int] = None
    security_model: Optional[str] = None
    community: Optional[str] = None
    source_interface: Optional[str] = None
    link_down_enabled: Optional[bool] = None
    link_up_enabled: Optional[bool] = None
    missing_config: List[str] = field(default_factory=list)
    changed: bool = False
    saved: bool = False
    status: str = "UNKNOWN"
    message: str = ""


# ============================================================================
# ANSI COLOR SUPPORT
# ============================================================================

class Color:
    """ANSI terminal colors."""
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    
    @staticmethod
    def status(text: str, status: str) -> str:
        """Apply color to status text."""
        if status == "PASS":
            return f"{Color.GREEN}{text}{Color.RESET}"
        elif status == "WARN":
            return f"{Color.YELLOW}{text}{Color.RESET}"
        elif status == "FAIL":
            return f"{Color.RED}{text}{Color.RESET}"
        return text


# ============================================================================
# ARGUMENT PARSING
# ============================================================================

def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Deploy and audit SNMP trap configuration on network devices"
    )
    parser.add_argument(
        "--inventory",
        required=True,
        help="Path to device inventory JSON file"
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply missing SNMP trap configuration (default: audit only)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed per-device information"
    )
    
    return parser.parse_args()


# ============================================================================
# INVENTORY MANAGEMENT
# ============================================================================

def load_inventory(inventory_file: str) -> List[Dict[str, Any]]:
    """Load and parse inventory JSON file."""
    try:
        with open(inventory_file, 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"✗ Inventory file not found: {inventory_file}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"✗ Invalid JSON in inventory file: {e}")
        sys.exit(1)
    
    if "devices" not in data or not isinstance(data["devices"], list):
        print("✗ Inventory must contain a 'devices' list")
        sys.exit(1)
    
    return data["devices"]


def validate_device_name(name: str) -> bool:
    """Validate device name for safety (no shell injection)."""
    # Allow alphanumeric and hyphens only
    return bool(re.match(r'^[a-zA-Z0-9\-]+$', name))


def validate_ipv4(ip: str) -> bool:
    """Validate IPv4 address format."""
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        return all(0 <= int(part) <= 255 for part in parts)
    except (ValueError, AttributeError):
        return False


def validate_inventory(devices_data: List[Dict[str, Any]]) -> List[Device]:
    """
    Validate inventory data and return selected router/switch devices.
    
    Returns list of Device objects for routers and switches.
    Exits with error if validation fails.
    """
    selected_devices = []
    seen_names = set()
    seen_ips = set()
    
    for device_dict in devices_data:
        # Check required fields
        if not all(k in device_dict for k in ["name", "ip", "type"]):
            print(f"✗ Device missing required fields: {device_dict}")
            sys.exit(1)
        
        device_name = device_dict["name"]
        device_ip = device_dict["ip"]
        device_type = device_dict["type"]
        device_role = device_dict.get("role", "unknown")
        
        # Validate device name
        if not validate_device_name(device_name):
            print(f"✗ Invalid device name (shell injection risk): {device_name}")
            sys.exit(1)
        
        # Validate IP address
        if not validate_ipv4(device_ip):
            print(f"✗ Invalid IPv4 address for {device_name}: {device_ip}")
            sys.exit(1)
        
        # Check for duplicate names
        if device_name in seen_names:
            print(f"✗ Duplicate device name in inventory: {device_name}")
            sys.exit(1)
        seen_names.add(device_name)
        
        # Check for duplicate IPs
        if device_ip in seen_ips:
            print(f"✗ Duplicate management IP in inventory: {device_ip}")
            sys.exit(1)
        seen_ips.add(device_ip)
        
        # Select only routers and switches
        if device_type in ["router", "switch"]:
            container_name = f"clab-pilot-network-{device_name}"
            device = Device(
                name=device_name,
                ip=device_ip,
                device_type=device_type,
                role=device_role,
                container_name=container_name
            )
            selected_devices.append(device)
    
    # Validate we have the expected devices
    device_names = {d.name for d in selected_devices}
    if device_names != REQUIRED_DEVICES:
        missing = REQUIRED_DEVICES - device_names
        extra = device_names - REQUIRED_DEVICES
        if missing:
            print(f"✗ Missing required devices: {missing}")
        if extra:
            print(f"✗ Unexpected extra devices: {extra}")
        sys.exit(1)
    
    if len(selected_devices) != EXPECTED_DEVICE_COUNT:
        print(f"✗ Expected {EXPECTED_DEVICE_COUNT} devices, found {len(selected_devices)}")
        sys.exit(1)
    
    return selected_devices


# ============================================================================
# PREREQUISITE CHECKS
# ============================================================================

def check_prerequisites() -> bool:
    """Verify that required tools exist."""
    print("[*] Checking prerequisites...")
    
    # Check docker command exists
    try:
        result = subprocess.run(
            ["docker", "--version"],
            capture_output=True,
            timeout=5
        )
        if result.returncode != 0:
            print("✗ docker command not available")
            return False
        print("    ✓ docker command found")
    except FileNotFoundError:
        print("✗ docker command not found")
        return False
    except Exception as e:
        print(f"✗ Error checking docker: {e}")
        return False
    
    return True


# ============================================================================
# DOCKER / EOS COMMAND EXECUTION
# ============================================================================

def run_eos_command(device: Device, command: str) -> tuple[bool, str]:
    """
    Execute an EOS command on a device via docker exec.
    
    Args:
        device: Device object
        command: EOS command to execute (e.g., "show hostname")
    
    Returns:
        Tuple of (success: bool, output: str)
    """
    try:
        # Use EOS CLI with privilege level 15
        cmd = [
            "docker", "exec",
            device.container_name,
            "Cli", "-p", "15",
            "-c", command
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT
        )
        
        if result.returncode == 0:
            return True, result.stdout.strip()
        else:
            error = result.stderr.strip() or "Command failed"
            return False, error
    
    except subprocess.TimeoutExpired:
        return False, "Command timeout"
    except Exception as e:
        return False, str(e)


def check_container(device: Device) -> bool:
    """Check if device container exists and is running."""
    try:
        # Check if container exists
        result = subprocess.run(
            ["docker", "ps", "-a", "--filter", f"name={device.container_name}"],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        if result.returncode != 0 or device.container_name not in result.stdout:
            return False
        
        # Check if container is running
        result = subprocess.run(
            ["docker", "ps", "--filter", f"name={device.container_name}"],
            capture_output=True,
            text=True,
            timeout=5
        )
        
        return result.returncode == 0 and device.container_name in result.stdout
    
    except Exception:
        return False


# ============================================================================
# SNMP CONFIGURATION AUDIT FUNCTIONS
# ============================================================================

def get_running_snmp_config(device: Device) -> str:
    """Get running SNMP configuration."""
    success, output = run_eos_command(device, "show running-config | include snmp")
    return output if success else ""


def get_notification_host(device: Device) -> tuple[Optional[str], Optional[int], Optional[str], Optional[str]]:
    """
    Query SNMP notification host configuration.
    
    Returns:
        Tuple of (host_ip, port, security_model, community)
    """
    success, output = run_eos_command(device, "show snmp notification host")
    
    if not success:
        return None, None, None, None
    
    host = None
    port = None
    security_model = None
    community = None
    
    # Parse output with proper format handling
    # Expected format:
    # Notification host: 172.20.20.1     udp-port: 162   type: trap   refresh: False
    # user: NetPilot                     security model: v2c
    
    lines = output.split('\n')
    for line in lines:
        line_lower = line.lower()
        
        # Parse first line: notification host and udp-port
        if 'notification host:' in line_lower:
            # Extract IP address
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                host = ip_match.group(1)
            
            # Extract UDP port
            port_match = re.search(r'udp-port:\s*(\d+)', line_lower)
            if port_match:
                port = int(port_match.group(1))
        
        # Parse user line with security model
        if 'user:' in line_lower:
            # Extract user/community value
            parts = line.split(':')
            if len(parts) >= 2:
                user_part = parts[1].strip()
                # Get value before any whitespace
                user_val = user_part.split()[0] if user_part else None
                if user_val:
                    community = user_val
            
            # Extract security model from same line
            if 'security model:' in line_lower:
                model_match = re.search(r'security\s+model:\s*(\S+)', line_lower)
                if model_match:
                    model_str = model_match.group(1).lower()
                    # Normalize: v2c -> 2c, v3 -> 3, 1 -> 1
                    if model_str.startswith('v'):
                        model_str = model_str[1:]
                    security_model = model_str
    
    return host, port, security_model, community


def get_local_interface(device: Device) -> Optional[str]:
    """Query SNMP local interface configuration."""
    success, output = run_eos_command(device, "show snmp local-interface")
    
    if not success:
        return None
    
    # Parse output for interface name
    # Expected format:
    # SNMP source interfaces:
    #    Management0 in VRF default
    
    lines = output.split('\n')
    for line in lines:
        # Look for interface names (Management0, Ethernet1, etc.)
        line_lower = line.lower()
        if 'management' in line_lower:
            # Extract the interface name (first word after stripping)
            parts = line.strip().split()
            if parts:
                iface = parts[0]
                return iface
    
    return None


def get_notification_status(device: Device) -> tuple[Optional[bool], Optional[bool]]:
    """
    Query SNMP trap notification status.
    
    Returns:
        Tuple of (link_down_enabled, link_up_enabled)
    """
    success, output = run_eos_command(device, "show snmp notification")
    
    if not success:
        return None, None
    
    link_down = None
    link_up = None
    
    # Parse output for link-down and link-up status
    # Expected format:
    # snmp                   link-down                               Yes (snmp enabled)
    # snmp                   link-up                                 Yes (snmp enabled)
    
    lines = output.split('\n')
    for line in lines:
        line_lower = line.lower()
        
        # Look for link-down notification
        if 'link-down' in line_lower:
            # Check if enabled
            if 'yes' in line_lower or 'enabled' in line_lower:
                link_down = True
            elif 'no' in line_lower or 'disabled' in line_lower:
                link_down = False
        
        # Look for link-up notification
        if 'link-up' in line_lower:
            # Check if enabled
            if 'yes' in line_lower or 'enabled' in line_lower:
                link_up = True
            elif 'no' in line_lower or 'disabled' in line_lower:
                link_up = False
    
    return link_down, link_up


# ============================================================================
# AUDIT FUNCTION
# ============================================================================

def audit_device(device: Device, verbose: bool = False) -> AuditResult:
    """
    Audit SNMP trap configuration on a device.
    
    Returns:
        AuditResult with current configuration state
    """
    result = AuditResult(device=device)
    
    # Check container
    if not check_container(device):
        result.container_running = False
        result.status = "FAIL"
        result.message = "Container not running"
        return result
    
    result.container_running = True
    
    # Audit configuration
    trap_host, trap_port, sec_model, comm = get_notification_host(device)
    result.trap_host = trap_host
    result.trap_port = trap_port
    result.security_model = sec_model
    result.community = comm
    
    result.source_interface = get_local_interface(device)
    link_down, link_up = get_notification_status(device)
    result.link_down_enabled = link_down
    result.link_up_enabled = link_up
    
    # Determine status based on critical configuration
    # CRITICAL: trap host, port, version, community, source interface
    # IMPORTANT: link notifications should be enabled
    
    if not result.container_running:
        result.status = "FAIL"
        result.message = "Container not running"
    elif (result.trap_host == NMAS_TRAP_RECEIVER and
          result.trap_port == TRAP_UDP_PORT and
          result.security_model == SNMP_VERSION and
          result.community == SNMP_COMMUNITY and
          result.source_interface and "management0" in result.source_interface.lower() and
          result.link_down_enabled is True and
          result.link_up_enabled is True):
        result.status = "PASS"
        result.message = "SNMP trap configuration is correct"
    elif result.trap_host is None:
        result.status = "FAIL"
        result.message = "SNMP trap host not configured"
    elif result.trap_host != NMAS_TRAP_RECEIVER or result.trap_port != TRAP_UDP_PORT:
        result.status = "FAIL"
        result.message = "Incorrect trap destination or port"
    elif result.security_model != SNMP_VERSION or result.community != SNMP_COMMUNITY:
        result.status = "FAIL"
        result.message = "Incorrect SNMP security parameters"
    elif not result.source_interface or "management0" not in result.source_interface.lower():
        result.status = "FAIL"
        result.message = "Source interface not configured correctly"
    elif result.link_down_enabled is False or result.link_up_enabled is False:
        result.status = "FAIL"
        result.message = "Link traps not enabled"
    else:
        result.status = "WARN"
        result.message = "Partial SNMP trap configuration"
    
    return result


# ============================================================================
# CONFIGURATION APPLICATION
# ============================================================================

def build_missing_config(result: AuditResult) -> List[str]:
    """
    Build list of missing configuration commands.
    
    Returns:
        List of EOS commands needed
    """
    commands = []
    
    # Check trap host configuration - add if ANY field is missing or incorrect
    # Must have: correct host, correct port, correct version, correct community
    if (result.trap_host is None or 
        result.trap_host != NMAS_TRAP_RECEIVER or 
        result.trap_port is None or
        result.trap_port != TRAP_UDP_PORT or
        result.security_model is None or
        result.security_model != SNMP_VERSION or 
        result.community is None or
        result.community != SNMP_COMMUNITY):
        commands.append(f"snmp-server host {NMAS_TRAP_RECEIVER} version {SNMP_VERSION} {SNMP_COMMUNITY}")
    
    # Check local interface - must be Management0
    if (result.source_interface is None or 
        "management0" not in result.source_interface.lower()):
        commands.append(f"snmp-server local-interface {SOURCE_INTERFACE}")
    
    # Check traps enabled - both link-down and link-up must be True
    # Add command if either is False or None (unknown)
    if (result.link_down_enabled is not True or 
        result.link_up_enabled is not True):
        commands.append("snmp-server enable traps snmp")
    
    return commands


def apply_device_config(device: Device, commands: List[str], verbose: bool = False) -> bool:
    """
    Apply configuration commands to a device.
    
    Returns:
        True if successful
    """
    if not commands:
        return True
    
    try:
        # Build configuration sequence using printf and bash piping
        # This is the proper way to send multi-line config to EOS Cli
        config_lines = ["enable", "configure"]
        config_lines.extend(commands)
        config_lines.append("end")
        config_lines.append("")  # Blank line at end
        
        # Create printf-compatible string (each line separated by \n)
        config_text = "\\n".join(config_lines)
        
        # Use docker exec with bash and printf to send config to Cli
        cmd = [
            "docker", "exec",
            device.container_name,
            "bash", "-c",
            f"printf '{config_text}' | Cli"
        ]
        
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=COMMAND_TIMEOUT
        )
        
        if result.returncode == 0:
            return True
        else:
            if verbose:
                error = result.stderr.strip() or result.stdout.strip() or "Command failed"
                print(f"      Configuration error: {error}")
            return False
    
    except subprocess.TimeoutExpired:
        if verbose:
            print(f"      Configuration timeout")
        return False
    except Exception as e:
        if verbose:
            print(f"      Configuration exception: {str(e)}")
        return False


def save_device_config(device: Device, verbose: bool = False) -> bool:
    """Save configuration to flash."""
    success, output = run_eos_command(device, "write memory")
    
    if not success and verbose:
        print(f"      Save error: {output}")
    
    return success


# ============================================================================
# OUTPUT FUNCTIONS
# ============================================================================

def print_header() -> None:
    """Print header with configuration summary."""
    print("\n" + "=" * 110)
    print(" " * 20 + "NetPilot SNMP Trap Configuration Audit")
    print("=" * 110)
    print(f"\nNMAS Trap Receiver : {NMAS_TRAP_RECEIVER}")
    print(f"UDP Port           : {TRAP_UDP_PORT}")
    print(f"SNMP Version       : {SNMP_VERSION}")
    print(f"Community          : {SNMP_COMMUNITY}")
    print(f"Managed Devices    : {EXPECTED_DEVICE_COUNT}")
    print()


def print_results_table(results: List[AuditResult]) -> None:
    """Print results in table format."""
    print("-" * 110)
    print(f"{'Device':<8} {'Mgmt IP':<15} {'Type':<8} {'Trap Host':<15} {'UDP':<6} {'Source':<12} "
          f"{'LinkDown':<10} {'LinkUp':<10} {'Change':<10} {'Status':<8}")
    print("-" * 110)
    
    for result in results:
        # Format fields
        device_name = result.device.name
        mgmt_ip = result.device.ip
        dev_type = result.device.device_type[:6]
        
        trap_host = result.trap_host or "N/A"
        udp_port = str(result.trap_port) if result.trap_port else "N/A"
        
        source_iface = result.source_interface or "N/A"
        if isinstance(source_iface, str) and "Management" in source_iface:
            source_iface = "Management0"
        
        link_down = "Enabled" if result.link_down_enabled else ("Disabled" if result.link_down_enabled is False else "N/A")
        link_up = "Enabled" if result.link_up_enabled else ("Disabled" if result.link_up_enabled is False else "N/A")
        
        change = "Applied" if result.changed else "None"
        if not result.container_running:
            change = "N/A"
        
        # Format status with color
        status_str = Color.status(result.status, result.status)
        
        print(f"{device_name:<8} {mgmt_ip:<15} {dev_type:<8} {trap_host:<15} {udp_port:<6} "
              f"{source_iface:<12} {link_down:<10} {link_up:<10} {change:<10} {status_str:<8}")
    
    print("-" * 110)


def print_device_details(result: AuditResult) -> None:
    """Print verbose details for a device."""
    print(f"\n[{result.device.name}]")
    print(f"\nContainer:")
    print(f"  {result.device.container_name}")
    print(f"\nManagement IP:")
    print(f"  {result.device.ip}")
    print(f"\nRole:")
    print(f"  {result.device.role}")
    
    print(f"\nAudit Results:")
    print(f"  Trap Host       : {result.trap_host or 'Not configured'}")
    print(f"  UDP Port        : {result.trap_port or 'Not configured'}")
    print(f"  Security Model  : {result.security_model or 'Not configured'}")
    print(f"  Community       : {result.community or 'Not configured'}")
    print(f"  Source Interface: {result.source_interface or 'Not configured'}")
    print(f"  linkDown        : {result.link_down_enabled if result.link_down_enabled is not None else 'Unknown'}")
    print(f"  linkUp          : {result.link_up_enabled if result.link_up_enabled is not None else 'Unknown'}")
    
    if result.missing_config:
        print(f"\nMissing Configuration:")
        for cmd in result.missing_config:
            print(f"  {cmd}")
    else:
        print(f"\nMissing Configuration:")
        print(f"  None")
    
    if result.changed:
        print(f"\nAction:")
        print(f"  Configuration applied and saved")
    else:
        print(f"\nAction:")
        print(f"  NO CHANGE REQUIRED")
    
    print(f"\nStatus: {result.status}")
    if result.message:
        print(f"Message: {result.message}")


def print_summary(results: List[AuditResult], apply_mode: bool = False) -> None:
    """Print summary statistics."""
    total = len(results)
    passed = sum(1 for r in results if r.status == "PASS")
    warned = sum(1 for r in results if r.status == "WARN")
    failed = sum(1 for r in results if r.status == "FAIL")
    changed = sum(1 for r in results if r.changed)
    correct = total - changed
    
    print("\n" + "-" * 110)
    print(f"Devices Checked : {total}")
    print(f"Passed          : {passed}")
    print(f"Warnings        : {warned}")
    print(f"Failed          : {failed}")
    if apply_mode:
        print(f"Changed         : {changed}")
        print(f"Already Correct : {correct}")
    
    print("\n" + "=" * 110)
    if failed == 0:
        print("RESULT: ALL 9 NETWORK DEVICES ARE CONFIGURED FOR SNMP TRAPS")
    else:
        print(f"RESULT: {failed} DEVICE(S) FAILED SNMP TRAP CONFIGURATION")
    print("=" * 110 + "\n")


# ============================================================================
# MAIN ORCHESTRATION
# ============================================================================

def main() -> int:
    """Main entry point."""
    # Parse arguments
    args = parse_arguments()
    
    print("\n[*] Initializing SNMP Trap Configuration Tool...\n")
    
    # Check prerequisites
    if not check_prerequisites():
        sys.exit(1)
    
    # Load and validate inventory
    print("[*] Loading inventory...")
    devices_data = load_inventory(args.inventory)
    devices = validate_inventory(devices_data)
    print(f"    ✓ Loaded {len(devices)} network devices (R1-R5, S1-S4)\n")
    
    # Sort devices for consistent output
    devices.sort(key=lambda d: (d.device_type, d.name))
    
    # Audit all devices
    print("[*] Auditing SNMP trap configuration...\n")
    results = []
    
    for device in devices:
        print(f"    [{device.name}] Checking...", end=" ", flush=True)
        
        # Audit device
        result = audit_device(device, args.verbose)
        
        # Calculate missing configuration (for both audit and apply modes)
        if result.container_running:
            missing = build_missing_config(result)
            result.missing_config = missing
        
        results.append(result)
        
        # If apply mode, deploy configuration
        if args.apply and result.container_running and result.missing_config:
            print("Applying configuration...", end=" ", flush=True)
            
            # Apply configuration
            if apply_device_config(device, result.missing_config, args.verbose):
                # Post-audit to verify
                result = audit_device(device, args.verbose)
                result.missing_config = build_missing_config(result)
                results[-1] = result
                
                # Save if post-audit passes
                if result.status == "PASS":
                    if save_device_config(device, args.verbose):
                        result.changed = True
                        result.saved = True
                        print("OK")
                    else:
                        print("SAVE FAILED")
                        result.status = "FAIL"
                        result.message = "Configuration applied but save failed"
                else:
                    print("POST-AUDIT FAILED")
                    result.status = "FAIL"
                    result.message = "Post-audit verification failed"
            else:
                print("APPLY FAILED")
                result.status = "FAIL"
                result.message = "Configuration application failed"
        else:
            print("OK")
        
        # Print verbose details if requested
        if args.verbose:
            print_device_details(result)
    
    # Print results
    print()
    print_header()
    print_results_table(results)
    print_summary(results, apply_mode=args.apply)
    
    # Determine exit code
    failed_count = sum(1 for r in results if r.status == "FAIL")
    return 0 if failed_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
