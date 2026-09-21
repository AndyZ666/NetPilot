#!/usr/bin/env python3
"""
Connectivity checker for Containerlab devices.
Tests ping connectivity to all management network devices.
"""

import subprocess
import sys
from typing import Dict, List, Tuple


class LabConnectivityChecker:
    """Check connectivity to containerlab devices."""
    
    # Define all devices and their management IPs
    DEVICES = {
        "R1": "172.20.20.13",
        "R2": "172.20.20.14",
        "R3": "172.20.20.9",
        "R4": "172.20.20.11",
        "R5": "172.20.20.2",
        "S1": "172.20.20.7",
        "S2": "172.20.20.8",
        "S3": "172.20.20.4",
        "S4": "172.20.20.10",
    }
    
    def __init__(self, timeout: int = 2, packet_count: int = 1):
        """
        Initialize the connectivity checker.
        
        Args:
            timeout: Timeout for each ping in seconds
            packet_count: Number of ping packets to send
        """
        self.timeout = timeout
        self.packet_count = packet_count
        self.results: Dict[str, Tuple[str, str]] = {}
    
    def check_device(self, device_name: str, ip_address: str) -> Tuple[str, str]:
        """
        Check connectivity to a single device using ping.
        
        Args:
            device_name: Name of the device
            ip_address: IP address to ping
            
        Returns:
            Tuple of (status, response_time) where status is "OK" or "FAILED"
        """
        try:
            # Use ping command (works on Linux, macOS, Windows)
            cmd = ["ping", "-c", str(self.packet_count), "-W", str(self.timeout * 1000), ip_address]
            result = subprocess.run(cmd, capture_output=True, timeout=self.timeout + 1)
            
            if result.returncode == 0:
                return "OK", ""
            else:
                return "FAILED", "No response"
        except subprocess.TimeoutExpired:
            return "FAILED", "Timeout"
        except Exception as e:
            return "FAILED", str(e)
    
    def check_all_devices(self) -> None:
        """Check connectivity to all devices."""
        print("\n" + "=" * 50)
        print("Containerlab Connectivity Check")
        print("=" * 50)
        print(f"{'Device':<10} {'IP Address':<20} {'Status':<15}")
        print("-" * 50)
        
        for device_name, ip_address in self.DEVICES.items():
            status, _ = self.check_device(device_name, ip_address)
            self.results[device_name] = (ip_address, status)
            
            # Format output
            status_indicator = "✓ OK" if status == "OK" else "✗ FAILED"
            print(f"{device_name:<10} {ip_address:<20} {status_indicator:<15}")
        
        print("=" * 50)
        self._print_summary()
        print("=" * 50 + "\n")
    
    def _print_summary(self) -> None:
        """Print connectivity summary."""
        total = len(self.results)
        online = sum(1 for _, status in self.results.values() if status == "OK")
        offline = total - online
        
        print(f"Total: {total} devices | Online: {online} | Offline: {offline}")
    
    def get_results(self) -> Dict[str, Tuple[str, str]]:
        """Return detailed results."""
        return self.results


def main():
    """Main entry point."""
    checker = LabConnectivityChecker(timeout=2, packet_count=1)
    checker.check_all_devices()
    
    # Check if all devices are online
    results = checker.get_results()
    all_online = all(status == "OK" for _, status in results.values())
    
    return 0 if all_online else 1


if __name__ == "__main__":
    sys.exit(main())
