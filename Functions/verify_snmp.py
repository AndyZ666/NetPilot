#!/usr/bin/env python3
"""
SNMP Verification Script for Network Devices

Verifies SNMP connectivity and data collection from all managed network devices.
Queries system info, CPU stats, interface status, and traffic counters.
Uses Net-SNMP snmpget/snmpwalk commands (requires net-snmp-utils installed).
"""

import json
import subprocess
import sys
import argparse
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional, Any
from pathlib import Path
from collections import defaultdict


# ============================================================================
# CONFIGURATION SECTION
# ============================================================================

SNMP_COMMUNITY = "NetPilot"
SNMP_TIMEOUT = 3  # seconds per command
SNMP_RETRIES = 1


# ============================================================================
# DATACLASSES FOR RESULTS
# ============================================================================

@dataclass
class InterfaceStatus:
    """Represents status of a single interface."""
    index: str
    name: str
    admin_status: str
    oper_status: str
    
    def is_operational(self) -> bool:
        """Check if interface is operationally up."""
        return self.oper_status == "UP"


@dataclass
class CPUStats:
    """Represents CPU statistics for a device."""
    avg: float
    min: float
    max: float
    processor_count: int
    raw_values: List[float] = field(default_factory=list)


@dataclass
class DeviceResult:
    """Represents the result of verifying a single device."""
    name: str
    ip: str
    status: str  # PASS, WARN, FAIL
    hostname_match: bool = False
    sys_descr: str = ""
    uptime_human: str = ""
    cpu_stats: Optional[CPUStats] = None
    interfaces_up: int = 0
    interfaces_total: int = 0
    interface_details: List[InterfaceStatus] = field(default_factory=list)
    traffic_counters_ok: bool = False
    error_message: str = ""


# ============================================================================
# ANSI COLOR CODES
# ============================================================================

class Color:
    """ANSI color codes for terminal output."""
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    
    @staticmethod
    def colorize(text: str, color: str) -> str:
        """Apply color to text. Returns plain text if color is empty."""
        if not color:
            return text
        return f"{color}{text}{Color.RESET}"


# ============================================================================
# SNMP COMMAND EXECUTION
# ============================================================================

def check_snmp_tools() -> bool:
    """
    Verify that snmpget and snmpwalk are installed.
    Prevents script execution if Net-SNMP tools are missing.
    """
    for tool in ['snmpget', 'snmpwalk']:
        try:
            result = subprocess.run(
                ['which', tool],
                capture_output=True,
                timeout=2
            )
            if result.returncode != 0:
                print(f"✗ Error: '{tool}' not found. Install net-snmp-utils.")
                return False
        except Exception as e:
            print(f"✗ Error checking for '{tool}': {e}")
            return False
    return True


def run_snmp_command(
    command: str,
    ip: str,
    oid: str,
    timeout: int = SNMP_TIMEOUT
) -> Tuple[bool, str]:
    """
    Execute snmpget or snmpwalk command against a device.
    
    Args:
        command: 'snmpget' or 'snmpwalk'
        ip: Device IP address
        oid: OID to query
        timeout: Command timeout in seconds
        
    Returns:
        Tuple of (success: bool, output: str)
        On failure, output contains error message
    """
    cmd = [
        command,
        '-v', '2c',
        '-c', SNMP_COMMUNITY,
        '-t', str(timeout),
        '-r', str(SNMP_RETRIES),
        ip,
        oid
    ]
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout + 1
        )
        
        if result.returncode == 0:
            return True, result.stdout.strip()
        else:
            error = result.stderr.strip() or "SNMP query failed"
            return False, error
            
    except subprocess.TimeoutExpired:
        return False, "SNMP command timeout"
    except FileNotFoundError:
        return False, f"Command '{command}' not found"
    except Exception as e:
        return False, f"Error: {str(e)}"


# ============================================================================
# SNMP DATA RETRIEVAL FUNCTIONS
# ============================================================================

def get_hostname(ip: str) -> Tuple[bool, str]:
    """
    Query sysName OID to get device hostname.
    Used to verify the device identity matches inventory.
    """
    success, output = run_snmp_command('snmpget', ip, '1.3.6.1.2.1.1.5.0')
    if not success:
        return False, output
    
    # Parse output: "SNMPv2-MIB::sysName.0 = STRING: "R1""
    try:
        # Extract the string value after "STRING: "
        if 'STRING:' in output:
            value = output.split('STRING:')[1].strip().strip('"')
            return True, value
        return False, "Could not parse hostname"
    except Exception as e:
        return False, str(e)


def get_sysdescr(ip: str) -> Tuple[bool, str]:
    """
    Query sysDescr OID to get detailed system description.
    Provides hardware/software identification for logging.
    """
    success, output = run_snmp_command('snmpget', ip, '1.3.6.1.2.1.1.1.0')
    if not success:
        return False, output
    
    try:
        if 'STRING:' in output:
            value = output.split('STRING:')[1].strip().strip('"')
            return True, value
        return False, "Could not parse system description"
    except Exception as e:
        return False, str(e)


def get_uptime(ip: str) -> Tuple[bool, str]:
    """
    Query sysUpTime OID and convert to human-readable format.
    sysUpTime is in hundredths of a second since device boot.
    """
    success, output = run_snmp_command('snmpget', ip, '1.3.6.1.2.1.1.3.0')
    if not success:
        return False, output
    
    try:
        # Extract the numeric value (hundredths of seconds)
        if 'Timeticks:' in output:
            # Format: "Timeticks: (123456789) 14 days, 06:45:23.45"
            timeticks = output.split('(')[1].split(')')[0]
            centiseconds = int(timeticks)
            
            # Convert to total seconds
            total_seconds = centiseconds // 100
            
            # Calculate days, hours, minutes, seconds
            days = total_seconds // 86400
            remainder = total_seconds % 86400
            hours = remainder // 3600
            remainder = remainder % 3600
            minutes = remainder // 60
            seconds = remainder % 60
            
            uptime_str = f"{days}d {hours:02d}h {minutes:02d}m"
            return True, uptime_str
        return False, "Could not parse uptime"
    except Exception as e:
        return False, str(e)


def get_cpu_stats(ip: str) -> Tuple[bool, CPUStats, str]:
    """
    Walk hrProcessorLoad OID to get CPU usage for all processors.
    Calculates average, minimum, maximum CPU load percentages.
    """
    success, output = run_snmp_command('snmpwalk', ip, '1.3.6.1.2.1.25.3.3.1.2')
    if not success:
        return False, None, output
    
    try:
        cpu_values = []
        lines = output.strip().split('\n')
        
        for line in lines:
            if not line.strip():
                continue
            # Parse: "HOST-RESOURCES-MIB::hrProcessorLoad.1 = INTEGER: 42"
            if 'INTEGER:' in line:
                value = int(line.split('INTEGER:')[1].strip())
                cpu_values.append(float(value))
        
        if not cpu_values:
            return False, None, "No CPU values retrieved"
        
        cpu_stats = CPUStats(
            avg=sum(cpu_values) / len(cpu_values),
            min=min(cpu_values),
            max=max(cpu_values),
            processor_count=len(cpu_values),
            raw_values=cpu_values
        )
        
        return True, cpu_stats, ""
        
    except Exception as e:
        return False, None, str(e)


def get_interfaces(ip: str) -> Tuple[bool, Dict[str, str], str]:
    """
    Walk ifDescr OID to build a mapping of ifIndex to interface names.
    This index is then used to correlate interface status data.
    """
    success, output = run_snmp_command('snmpwalk', ip, '1.3.6.1.2.1.2.2.1.2')
    if not success:
        return False, {}, output
    
    try:
        interfaces = {}
        lines = output.strip().split('\n')
        
        for line in lines:
            if not line.strip():
                continue
            # Parse: "IF-MIB::ifDescr.1 = STRING: "Ethernet1""
            try:
                # Extract ifIndex from OID
                oid_part = line.split(' = ')[0]
                if_index = oid_part.split('.')[-1]
                
                # Extract interface name
                if 'STRING:' in line:
                    if_name = line.split('STRING:')[1].strip().strip('"')
                    interfaces[if_index] = if_name
            except:
                continue
        
        if not interfaces:
            return False, {}, "No interfaces found"
        
        return True, interfaces, ""
        
    except Exception as e:
        return False, {}, str(e)


def get_interface_status(
    ip: str,
    if_index_map: Dict[str, str]
) -> Tuple[bool, List[InterfaceStatus], str]:
    """
    Walk ifAdminStatus and ifOperStatus OIDs to get interface status.
    Correlates status data with interface names using ifIndex mapping.
    """
    # Get administrative status
    success_admin, admin_output = run_snmp_command(
        'snmpwalk', ip, '1.3.6.1.2.1.2.2.1.7'
    )
    
    # Get operational status
    success_oper, oper_output = run_snmp_command(
        'snmpwalk', ip, '1.3.6.1.2.1.2.2.1.8'
    )
    
    if not success_admin or not success_oper:
        error = admin_output if not success_admin else oper_output
        return False, [], error
    
    try:
        # Parse admin status
        admin_status = {}
        for line in admin_output.strip().split('\n'):
            if not line.strip():
                continue
            try:
                oid_part = line.split(' = ')[0]
                if_index = oid_part.split('.')[-1]
                value = line.split('INTEGER:')[1].strip()
                admin_status[if_index] = _map_status(value)
            except:
                continue
        
        # Parse operational status
        oper_status = {}
        for line in oper_output.strip().split('\n'):
            if not line.strip():
                continue
            try:
                oid_part = line.split(' = ')[0]
                if_index = oid_part.split('.')[-1]
                value = line.split('INTEGER:')[1].strip()
                oper_status[if_index] = _map_status(value)
            except:
                continue
        
        # Correlate interface status
        interface_list = []
        for if_index, if_name in if_index_map.items():
            admin = admin_status.get(if_index, "UNKNOWN")
            oper = oper_status.get(if_index, "UNKNOWN")
            interface_list.append(
                InterfaceStatus(if_index, if_name, admin, oper)
            )
        
        return True, interface_list, ""
        
    except Exception as e:
        return False, [], str(e)


def _map_status(value: str) -> str:
    """Convert SNMP status integer to human-readable string."""
    status_map = {"1": "UP", "2": "DOWN", "3": "TESTING"}
    # Handle both numeric and text formats
    value_clean = value.split('(')[0].strip()
    return status_map.get(value_clean, value_clean)


def check_traffic_counters(ip: str) -> Tuple[bool, str]:
    """
    Verify that high-capacity traffic counters can be retrieved.
    This is a read-only verification; does not modify device state.
    """
    # Check ifHCInOctets
    success_in, _ = run_snmp_command('snmpget', ip, '1.3.6.1.2.1.31.1.1.1.6.1')
    
    # Check ifHCOutOctets
    success_out, _ = run_snmp_command('snmpget', ip, '1.3.6.1.2.1.31.1.1.1.10.1')
    
    if success_in and success_out:
        return True, ""
    
    # If walk fails, it might be due to missing interface 1; try to walk instead
    success_in, _ = run_snmp_command('snmpwalk', ip, '1.3.6.1.2.1.31.1.1.1.6')
    success_out, _ = run_snmp_command('snmpwalk', ip, '1.3.6.1.2.1.31.1.1.1.10')
    
    if success_in and success_out:
        return True, ""
    
    return False, "Cannot retrieve traffic counters"


# ============================================================================
# DEVICE VERIFICATION
# ============================================================================

def verify_device(device: Dict[str, Any], verbose: bool = False) -> DeviceResult:
    """
    Perform comprehensive SNMP verification for a single device.
    Queries all required OIDs and determines PASS/WARN/FAIL status.
    Device failures do not prevent checking remaining devices.
    """
    result = DeviceResult(
        name=device['name'],
        ip=device['ip'],
        status="FAIL"
    )
    
    # Step 1: Verify hostname matches
    success, hostname = get_hostname(result.ip)
    if not success:
        result.error_message = hostname
        return result
    
    # Verify hostname matches device name
    if hostname.lower() != result.name.lower():
        result.error_message = f"Hostname mismatch: expected {result.name}, got {hostname}"
        return result
    
    result.hostname_match = True
    
    # Step 2: Get system description
    success, sys_descr = get_sysdescr(result.ip)
    if success:
        result.sys_descr = sys_descr
    
    # Step 3: Get uptime
    success, uptime = get_uptime(result.ip)
    if success:
        result.uptime_human = uptime
    else:
        result.error_message = uptime
        return result
    
    # Step 4: Get CPU statistics
    success, cpu_stats, error = get_cpu_stats(result.ip)
    if not success:
        result.error_message = f"CPU query failed: {error}"
        return result
    
    result.cpu_stats = cpu_stats
    
    # Step 5: Get interface information
    success, if_map, error = get_interfaces(result.ip)
    if not success:
        result.error_message = f"Interface query failed: {error}"
        return result
    
    # Step 6: Get interface status
    success, interface_list, error = get_interface_status(result.ip, if_map)
    if not success:
        result.error_message = f"Interface status query failed: {error}"
        return result
    
    result.interface_details = interface_list
    result.interfaces_total = len(interface_list)
    result.interfaces_up = sum(1 for iface in interface_list if iface.is_operational())
    
    # Step 7: Check traffic counters
    success, error = check_traffic_counters(result.ip)
    result.traffic_counters_ok = success
    
    # Determine device status based on verification results
    if result.interfaces_up < result.interfaces_total:
        result.status = "WARN"
    elif not result.traffic_counters_ok:
        result.status = "WARN"
    else:
        result.status = "PASS"
    
    return result


# ============================================================================
# OUTPUT FORMATTING
# ============================================================================

def format_device_row(result: DeviceResult) -> str:
    """Format a single device result for table output."""
    # Determine color based on status
    if result.status == "PASS":
        status_colored = Color.colorize(result.status, Color.GREEN)
    elif result.status == "WARN":
        status_colored = Color.colorize(result.status, Color.YELLOW)
    else:
        status_colored = Color.colorize(result.status, Color.RED)
    
    # Format interface count
    if result.interfaces_total > 0:
        interface_str = f"{result.interfaces_up}/{result.interfaces_total} UP"
    else:
        interface_str = "N/A"
    
    # Format CPU
    if result.cpu_stats:
        cpu_str = f"{result.cpu_stats.avg:.1f}%"
    else:
        cpu_str = "N/A"
    
    # Build row with fixed-width columns
    row = (
        f"{result.name:<8} "
        f"{result.ip:<18} "
        f"{result.name:<10} "
        f"{cpu_str:<10} "
        f"{interface_str:<12} "
        f"{result.uptime_human:<12} "
        f"{status_colored}"
    )
    
    return row


def print_results_table(results: List[DeviceResult]) -> None:
    """Print formatted table of device verification results."""
    print("\n" + "=" * 100)
    print("SNMP Verification Results")
    print("=" * 100)
    
    # Print header
    header = (
        f"{'Device':<8} "
        f"{'Management IP':<18} "
        f"{'Hostname':<10} "
        f"{'CPU Avg':<10} "
        f"{'Interfaces':<12} "
        f"{'Uptime':<12} "
        f"{'Status'}"
    )
    print(header)
    print("-" * 100)
    
    # Print device rows
    for result in results:
        print(format_device_row(result))
    
    print("=" * 100)


def print_verbose_output(result: DeviceResult) -> None:
    """
    Print detailed information for a device in verbose mode.
    Includes system description, CPU details, and interface information.
    """
    print(f"\n{'='*70}")
    print(f"Device: {result.name} ({result.ip})")
    print(f"{'='*70}")
    
    print(f"Status: {result.status}")
    print(f"Hostname Match: {'✓' if result.hostname_match else '✗'}")
    
    if result.sys_descr:
        print(f"System Description: {result.sys_descr}")
    
    print(f"Uptime: {result.uptime_human}")
    
    if result.cpu_stats:
        print(f"\nCPU Statistics:")
        print(f"  Processor Count: {result.cpu_stats.processor_count}")
        print(f"  Average Load: {result.cpu_stats.avg:.2f}%")
        print(f"  Minimum Load: {result.cpu_stats.min:.2f}%")
        print(f"  Maximum Load: {result.cpu_stats.max:.2f}%")
        print(f"  Raw Values: {[f'{v:.0f}%' for v in result.cpu_stats.raw_values]}")
    
    if result.interface_details:
        print(f"\nInterfaces ({result.interfaces_up}/{result.interfaces_total} operational):")
        for iface in sorted(result.interface_details, key=lambda x: x.name):
            oper_symbol = "✓" if iface.is_operational() else "✗"
            print(f"  {oper_symbol} {iface.name:<12} Admin: {iface.admin_status:<8} Oper: {iface.oper_status}")
    
    if result.traffic_counters_ok:
        print(f"\nTraffic Counters: ✓ Available")
    else:
        print(f"\nTraffic Counters: ✗ Not available")
    
    if result.error_message:
        print(f"Error: {result.error_message}")


def print_summary(results: List[DeviceResult]) -> None:
    """Print summary statistics of verification results."""
    total = len(results)
    passed = sum(1 for r in results if r.status == "PASS")
    warned = sum(1 for r in results if r.status == "WARN")
    failed = sum(1 for r in results if r.status == "FAIL")
    
    print("\n" + "=" * 100)
    print("Summary")
    print("=" * 100)
    print(f"Devices checked:  {total}")
    print(f"Passed:           {Color.colorize(str(passed), Color.GREEN)}")
    print(f"Warnings:         {Color.colorize(str(warned), Color.YELLOW)}")
    print(f"Failed:           {Color.colorize(str(failed), Color.RED)}")
    print("=" * 100)
    
    if failed == 0:
        print(f"\n{Color.colorize('✓ RESULT: ALL SNMP MONITORING CHECKS PASSED', Color.GREEN)}\n")
    else:
        print(f"\n{Color.colorize('✗ RESULT: ONE OR MORE DEVICES FAILED SNMP VERIFICATION', Color.RED)}\n")


# ============================================================================
# MAIN ORCHESTRATION
# ============================================================================

def load_devices(devices_file: Path) -> List[Dict[str, Any]]:
    """Load device inventory from devices.json."""
    try:
        with open(devices_file, 'r') as f:
            data = json.load(f)
            devices = data.get('devices', [])
            # Filter only routers and switches for SNMP monitoring
            monitored = [d for d in devices if d['type'] in ['router', 'switch']]
            return monitored
    except Exception as e:
        print(f"✗ Error loading devices: {e}")
        sys.exit(1)


def main():
    """Main entry point for SNMP verification script."""
    parser = argparse.ArgumentParser(
        description="Verify SNMP connectivity and monitoring capability for network devices"
    )
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help="Show detailed information for each device"
    )
    
    args = parser.parse_args()
    
    # Get script directory
    script_dir = Path(__file__).parent
    devices_file = script_dir / "devices.json"
    
    print("Initializing SNMP Verification...\n")
    
    # Check prerequisites
    print("[*] Checking Net-SNMP tools...")
    if not check_snmp_tools():
        sys.exit(1)
    print("    ✓ snmpget and snmpwalk found\n")
    
    # Load device inventory
    print("[*] Loading device inventory...")
    devices = load_devices(devices_file)
    if not devices:
        print("✗ No devices found to verify")
        sys.exit(1)
    print(f"    ✓ Loaded {len(devices)} network devices\n")
    
    # Verify all devices
    print("[*] Verifying SNMP connectivity to each device...\n")
    results = []
    
    for i, device in enumerate(devices, 1):
        print(f"    [{i}/{len(devices)}] Checking {device['name']} ({device['ip']})...", end=" ", flush=True)
        result = verify_device(device, verbose=args.verbose)
        results.append(result)
        
        # Show status immediately
        if result.status == "PASS":
            print(Color.colorize("✓", Color.GREEN))
        elif result.status == "WARN":
            print(Color.colorize("⚠", Color.YELLOW))
        else:
            print(Color.colorize("✗", Color.RED))
            if result.error_message:
                print(f"      Error: {result.error_message}")
    
    # Print results table
    print_results_table(results)
    
    # Print verbose details if requested
    if args.verbose:
        for result in results:
            print_verbose_output(result)
    
    # Print summary
    print_summary(results)
    
    # Determine exit code
    failed_count = sum(1 for r in results if r.status == "FAIL")
    return 0 if failed_count == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
