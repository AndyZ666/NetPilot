#!/usr/bin/env python3
"""
Deploy SNMP configuration to all routers and switches.
Reads device information from devices.json and configures SNMP.
"""

import json
import subprocess
import sys
from typing import Dict, List, Any
from pathlib import Path


class SNMPDeployer:
    """Deploy SNMP configuration to network devices."""
    
    # SNMP configuration commands
    SNMP_COMMANDS = [
        "snmp-server community NetPilot ro"
    ]
    
    def __init__(self, devices_file: str = "devices.json"):
        """
        Initialize the SNMP deployer.
        
        Args:
            devices_file: Path to devices.json file
        """
        self.devices_file = devices_file
        self.devices: List[Dict[str, Any]] = []
        self.results: Dict[str, Dict[str, Any]] = {}
        self.load_devices()
    
    def load_devices(self) -> None:
        """Load devices from JSON file."""
        try:
            with open(self.devices_file, 'r') as f:
                data = json.load(f)
                self.devices = data.get('devices', [])
                print(f"✓ Loaded {len(self.devices)} devices from {self.devices_file}")
        except FileNotFoundError:
            print(f"✗ Error: {self.devices_file} not found")
            sys.exit(1)
        except json.JSONDecodeError:
            print(f"✗ Error: Invalid JSON in {self.devices_file}")
            sys.exit(1)
    
    def get_target_devices(self) -> List[Dict[str, Any]]:
        """Get only routers and switches (exclude hosts and servers)."""
        return [d for d in self.devices if d['type'] in ['router', 'switch']]
    
    def deploy_snmp_to_device(self, device: Dict[str, Any]) -> bool:
        """
        Deploy SNMP configuration to a single device using docker exec and CLI.
        
        Args:
            device: Device information dictionary
            
        Returns:
            True if successful, False otherwise
        """
        device_name = device['name']
        docker_name = f"clab-pilot-network-{device_name}"
        
        try:
            # Build CLI commands: enable -> configure -> SNMP commands -> end
            cli_commands = "enable\nconfigure\n"
            cli_commands += "\n".join(self.SNMP_COMMANDS)
            cli_commands += "\nend\n"
            
            # Deploy configuration using bash piping
            deploy_cmd = [
                "docker", "exec", docker_name, "bash", "-c",
                f"printf \"{cli_commands}\" | Cli"
            ]
            
            deploy_result = subprocess.run(
                deploy_cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Verify configuration was applied
            verify_cli = "enable\nshow running-config | section snmp\n"
            verify_cmd = [
                "docker", "exec", docker_name, "bash", "-c",
                f"printf \"{verify_cli}\" | Cli"
            ]
            
            verify_result = subprocess.run(
                verify_cmd,
                capture_output=True,
                text=True,
                timeout=10
            )
            
            # Check if SNMP config is in output
            if "snmp-server community NetPilot ro" in verify_result.stdout:
                self.results[device_name] = {
                    "status": "OK",
                    "output": verify_result.stdout.strip(),
                    "error": None
                }
                return True
            else:
                self.results[device_name] = {
                    "status": "FAILED",
                    "output": verify_result.stdout.strip(),
                    "error": "SNMP configuration not found in running config"
                }
                return False
                
        except subprocess.TimeoutExpired:
            self.results[device_name] = {
                "status": "TIMEOUT",
                "output": "",
                "error": "Command execution timeout"
            }
            return False
        except Exception as e:
            self.results[device_name] = {
                "status": "ERROR",
                "output": "",
                "error": str(e)
            }
            return False
    
    def deploy_all(self) -> None:
        """Deploy SNMP configuration to all target devices."""
        target_devices = self.get_target_devices()
        
        print("\n" + "=" * 80)
        print("SNMP Deployment - Routers and Switches")
        print("=" * 80)
        print(f"Target Devices: {len(target_devices)}\n")
        
        successful = 0
        failed = 0
        
        for device in target_devices:
            device_name = device['name']
            device_type = device['type'].upper()
            
            print(f"\n[*] Deploying to {device_name} ({device_type})...")
            
            if self.deploy_snmp_to_device(device):
                successful += 1
                print(f"    ✓ Status: OK")
                print(f"    ✓ Configuration:")
                output = self.results[device_name]['output']
                if output:
                    for line in output.split('\n'):
                        if line.strip():
                            print(f"      {line}")
                else:
                    print(f"      snmp-server community NetPilot ro")
            else:
                failed += 1
                print(f"    ✗ Status: FAILED")
                error = self.results[device_name]['error']
                if error:
                    print(f"    ✗ Error: {error}")
        
        # Print summary
        print("\n" + "=" * 80)
        print("SNMP Deployment Summary")
        print("=" * 80)
        print(f"Total Devices: {len(target_devices)}")
        print(f"Successful: {successful}")
        print(f"Failed: {failed}")
        print("=" * 80 + "\n")
    
    def get_results(self) -> Dict[str, Dict[str, Any]]:
        """Return deployment results."""
        return self.results


def main():
    """Main entry point."""
    # Get the directory where this script is located
    script_dir = Path(__file__).parent
    devices_file = script_dir / "devices.json"
    
    deployer = SNMPDeployer(str(devices_file))
    deployer.deploy_all()
    
    # Return 0 if all successful, 1 otherwise
    results = deployer.get_results()
    failed = sum(1 for r in results.values() if r['status'] != 'OK')
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
