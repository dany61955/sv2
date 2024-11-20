from netmiko import ConnectHandler
from netmiko import NetMikoTimeoutException, NetMikoAuthenticationException
import time
import getpass
import os
from pathlib import Path
from datetime import datetime
from typing import List, Tuple, Dict
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import re
from difflib import HtmlDiff
from dataclasses import dataclass
from retry import retry
from jinja2 import Environment, FileSystemLoader
import difflib

@dataclass
class DeviceCredentials:
    hostname: str
    username: str
    password: str
    enable_password: str = None

class SNMPMigration:
    def __init__(self):
        # Initialize logger
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        
        # Clear any existing handlers
        self.logger.handlers = []
        
        # Simple formatters without hostname
        file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_formatter = logging.Formatter('%(message)s')
        
        # File handler for detailed logging
        file_handler = logging.FileHandler('snmp_migration.log', mode='a')
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(file_formatter)
        
        # Console handler for minimal logging
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(console_formatter)
        
        # Add handlers
        self.logger.addHandler(file_handler)
        self.logger.addHandler(console_handler)
        
        # Create directories for backups and logs
        self.backup_dir = Path('backups')
        self.logs_dir = Path('logs')
        self.backup_dir.mkdir(exist_ok=True)
        self.logs_dir.mkdir(exist_ok=True)
        
        # Get timestamp once for consistent naming
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        self.device_diffs = {}
        self.snmp_server_hosts_file = "snmp_server_host.txt"
        self.snmpv3_username = None
        
        # Setup Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader('templates'),
            autoescape=True
        )
        
    def log_with_hostname(self, hostname: str, level: int, message: str):
        """Helper method to log messages with hostname"""
        formatted_message = f"[{hostname}] {message}"
        self.logger.log(level, formatted_message)

    @retry(tries=3, delay=2, backoff=2)
    def send_commands_to_device(self, hostname: str, username: str, password: str, 
                              commands: List[str], config_mode: bool = False) -> Tuple[List[str], bool, str]:
        """Send commands to device using Netmiko"""
        logs = []
        success = False
        output = ""
        
        # Create session log path
        session_log = self.logs_dir / f'{hostname}_{self.timestamp}_session.log'
        
        device = {
            'device_type': 'cisco_ios',
            'host': hostname,
            'username': username,
            'password': password,
            'timeout': 120,
            'session_log': str(session_log)
        }
        
        try:
            with ConnectHandler(**device) as connection:
                if config_mode:
                    output = connection.send_config_set(
                        commands,
                        enter_config_mode=True,
                        exit_config_mode=True,
                        cmd_verify=False
                    )
                    logs.append(output)
                    self.log_with_hostname(hostname, logging.DEBUG, f"Config commands output:\n{output}")
                else:
                    for command in commands:
                        cmd_output = connection.send_command(
                            command,
                            strip_prompt=True,
                            strip_command=True
                        )
                        output += cmd_output + "\n"
                        logs.append(cmd_output)
                        self.log_with_hostname(hostname, logging.DEBUG, f"Command '{command}' output:\n{cmd_output}")
                
                success = True

        except NetMikoTimeoutException:
            self.log_with_hostname(hostname, logging.ERROR, "Connection timeout")
            logs.append("Error: Connection timeout")
        except NetMikoAuthenticationException:
            self.log_with_hostname(hostname, logging.ERROR, "Authentication failed")
            logs.append("Error: Authentication failed")
        except Exception as e:
            self.log_with_hostname(hostname, logging.ERROR, f"Error: {str(e)}")
            logs.append(f"Error: {str(e)}")
        
        return logs, success, output

    def get_snmp_host_config(self, hostname: str, username: str, password: str) -> Tuple[List[str], str]:
        """Get current SNMP host configuration and detect VRF if present"""
        command = "show run | i snmp-server.*host"
        _, _, output = self.send_commands_to_device(hostname, username, password, [command])
        
        # Read target IPs from snmp_server_host.txt
        with open(self.snmp_server_hosts_file) as f:
            target_ips = {line.strip() for line in f if line.strip()}
        
        vrf_name = None
        host_commands = []
        
        # Process each line of output
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
                
            # Check for Format1 (with VRF)
            vrf_match = re.search(r'snmp-server host (\S+) vrf (\S+) (\S+)', line)
            if vrf_match:
                ip, vrf, community = vrf_match.groups()
                # Only process if IP is in our target list
                if ip in target_ips:
                    host_commands.append(f"no {line}")
                    if not vrf_name:
                        vrf_name = vrf
                continue
                
            # Check for Format2 (without VRF)
            basic_match = re.search(r'snmp-server host (\S+) (\S+)', line)
            if basic_match:
                ip = basic_match.group(1)
                # Only process if IP is in our target list
                if ip in target_ips:
                    host_commands.append(f"no {line}")
        
        self.logger.info(f"{hostname}: Found {len(host_commands)} matching SNMP host configurations to remove")
        return host_commands, vrf_name

    def generate_snmp_commands(self, hostname: str, username: str, password: str) -> Tuple[List[str], List[str]]:
        """Generate combined SNMP commands for both v2 removal and v3 addition"""
        # Read static commands
        with open("snmpv2_remove.txt") as f:
            static_v2_remove = [line.strip() for line in f if line.strip()]
            
        with open("snmpv3_add.txt") as f:
            static_v3_add = [line.strip() for line in f if line.strip()]
            
        # Replace placeholder with actual SNMPv3 username in static commands
        static_v3_add = [cmd.replace('SNMPV3USER', self.snmpv3_username) for cmd in static_v3_add]
            
        with open(self.snmp_server_hosts_file) as f:
            server_ips = [line.strip() for line in f if line.strip()]
            
        # Get dynamic host commands and VRF info
        dynamic_v2_remove, vrf_name = self.get_snmp_host_config(hostname, username, password)
        
        # Combine v2 removal commands
        snmpv2_commands = static_v2_remove + dynamic_v2_remove
        
        # Generate v3 commands with VRF if needed
        snmpv3_commands = static_v3_add.copy()
        for ip in server_ips:
            if vrf_name:
                snmpv3_commands.append(f"snmp-server host {ip} vrf {vrf_name} version 3 priv {self.snmpv3_username}")
            else:
                snmpv3_commands.append(f"snmp-server host {ip} version 3 priv {self.snmpv3_username}")
                
        return snmpv2_commands, snmpv3_commands

    def configure_snmp(self, hostname: str, username: str, password: str) -> Tuple[List[str], bool]:
        """Configure SNMP on device"""
        try:
            print(f"Processing {hostname}...", end=' ', flush=True)
            self.log_with_hostname(hostname, logging.DEBUG, "Starting SNMP configuration")
            
            # Generate commands
            snmpv2_commands, snmpv3_commands = self.generate_snmp_commands(hostname, username, password)
            
            # Create backup
            backup_success = self.create_backup(hostname, username, password)
            if not backup_success:
                print("Failed (Backup)")
                self.log_with_hostname(hostname, logging.ERROR, "Backup failed")
                return [], False
                
            # Apply SNMPv2 removal commands
            logs_v2, success_v2, _ = self.send_commands_to_device(
                hostname, username, password, snmpv2_commands, config_mode=True
            )
            
            if not success_v2:
                print("Failed (SNMPv2)")
                self.log_with_hostname(hostname, logging.ERROR, "Failed to remove SNMPv2 configuration")
                return logs_v2, False
                
            # Apply SNMPv3 commands
            logs_v3, success_v3, _ = self.send_commands_to_device(
                hostname, username, password, snmpv3_commands, config_mode=True
            )
            
            success = success_v2 and success_v3
            if success:
                print("Success")
                self.log_with_hostname(hostname, logging.INFO, "SNMP migration completed successfully")
                # Save after configuration
                self.save_after_config(hostname, username, password)
            else:
                print("Failed (SNMPv3)")
                self.log_with_hostname(hostname, logging.ERROR, "Failed during SNMPv3 configuration")
                
            return logs_v2 + logs_v3, success
            
        except Exception as e:
            print(f"Failed ({str(e)})")
            self.log_with_hostname(hostname, logging.ERROR, f"Error during SNMP configuration: {str(e)}")
            return [], False

    def generate_index_html(self) -> str:
        """Generate index.html using Jinja2 template"""
        try:
            index_file = self.backup_dir / 'index.html'
            
            # Sort devices by timestamp (most recent first)
            sorted_devices = dict(sorted(
                self.device_diffs.items(),
                key=lambda x: x[1].get('timestamp', ''),
                reverse=True
            ))
            
            # Count successes and failures
            total = len(self.device_diffs)
            success_count = len([d for d in self.device_diffs.values() if d['success']])
            failed_count = total - success_count
            
            # Log the counts for verification
            self.logger.info(f"Generating index with: Total={total}, Success={success_count}, Failed={failed_count}")
            
            # Render template
            template = self.jinja_env.get_template('index.html.j2')
            html_content = template.render(
                timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                total=total,
                success=success_count,
                failed=failed_count,
                devices=sorted_devices
            )
            
            # Write the index file
            with open(index_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"Index file updated at {index_file}")
            return str(index_file)
            
        except Exception as e:
            self.logger.error(f"Failed to generate index file: {str(e)}")
            return ""

    def process_devices_parallel(self, device_list: List[str], username: str, password: str) -> List[Tuple[str, bool]]:
        """Process multiple devices in parallel"""
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for device in device_list:
                future = executor.submit(self.configure_snmp, device, username, password)
                futures.append((device, future))
                
            results = []
            for device, future in futures:
                try:
                    logs, success = future.result()
                    results.append((device, success))
                except Exception as e:
                    self.logger.error(f"Error processing {device}: {str(e)}")
                    results.append((device, False))
                    
        return results

    def create_backup(self, hostname: str, username: str, password: str) -> bool:
        """Create before configuration backup"""
        try:
            # Create hostname-specific directory
            host_backup_dir = self.backup_dir / hostname
            host_backup_dir.mkdir(exist_ok=True)
            
            # Get current configuration
            command = "show running-config"
            _, success, output = self.send_commands_to_device(
                hostname, username, password, [command], config_mode=False
            )
            
            if not success:
                self.logger.error(f"{hostname}: Failed to get configuration")
                return False
            
            # Save before configuration
            before_file = host_backup_dir / f"before_{self.timestamp}.txt"
            with open(before_file, 'w') as f:
                f.write(output)
            
            self.logger.debug(f"{hostname}: Before configuration saved at {before_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"{hostname}: Error creating backup: {str(e)}")
            return False

    def save_after_config(self, hostname: str, username: str, password: str) -> bool:
        """Save after configuration and generate diff"""
        try:
            host_backup_dir = self.backup_dir / hostname
            
            # Get current configuration
            command = "show running-config"
            _, success, output = self.send_commands_to_device(
                hostname, username, password, [command], config_mode=False
            )
            
            if not success:
                self.log_with_hostname(hostname, logging.ERROR, "Failed to get after configuration")
                return False
                
            # Save after configuration
            after_file = host_backup_dir / f"after_{self.timestamp}.txt"
            with open(after_file, 'w') as f:
                f.write(output)
                
            # Generate diff
            before_file = host_backup_dir / f"before_{self.timestamp}.txt"
            if before_file.exists():
                try:
                    with open(before_file) as f:
                        before_text = f.readlines()
                    with open(after_file) as f:
                        after_text = f.readlines()
                        
                    # Generate diff using HtmlDiff
                    differ = difflib.HtmlDiff()
                    diff_table = differ.make_file(
                        before_text,
                        after_text,
                        fromdesc='Before Changes',
                        todesc='After Changes',
                        context=True,
                        numlines=3
                    )
                    
                    # Render diff template
                    diff_template = self.jinja_env.get_template('diff.html.j2')
                    diff_html = diff_template.render(
                        hostname=hostname,
                        timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        lines_added=sum(1 for line in after_text if line not in before_text),
                        lines_removed=sum(1 for line in before_text if line not in after_text),
                        lines_changed=0,  # This would need more complex logic to determine
                        diff_table=diff_table
                    )
                    
                    # Save diff file
                    diff_file = host_backup_dir / f"diff_{self.timestamp}.html"
                    with open(diff_file, 'w') as f:
                        f.write(diff_html)
                        
                    self.log_with_hostname(hostname, logging.INFO, f"Generated diff file at {diff_file}")
                    
                except Exception as e:
                    self.log_with_hostname(hostname, logging.ERROR, f"Error generating diff: {str(e)}")
            
            return True
            
        except Exception as e:
            self.log_with_hostname(hostname, logging.ERROR, f"Error saving after config: {str(e)}")
            return False

    def generate_html_report(self, results: List[Tuple[str, bool]]) -> None:
        """Generate HTML index using Jinja template"""
        try:
            total = len(results)
            success = sum(1 for _, status in results if status)
            failed = total - success
            
            # Prepare data for template
            devices_data = []
            for hostname, status in results:
                host_backup_dir = self.backup_dir / hostname
                devices_data.append({
                    'hostname': hostname,
                    'status': status,
                    'before_file': f"backups/{hostname}/before_{self.timestamp}.txt",
                    'after_file': f"backups/{hostname}/after_{self.timestamp}.txt",
                    'diff_file': f"backups/{hostname}/diff_{self.timestamp}.html",
                    'session_log': f"logs/{hostname}_{self.timestamp}_session.log"
                })
            
            # Render index template
            template = self.jinja_env.get_template('index.html.j2')
            index_html = template.render(
                timestamp=self.timestamp,
                total=total,
                success=success,
                failed=failed,
                devices=devices_data
            )
            
            # Save index file
            with open('index.html', 'w') as f:
                f.write(index_html)
                
            self.logger.info("Index file generated at index.html")
            
        except Exception as e:
            self.logger.error(f"Error generating HTML report: {str(e)}")

def main():
    # Set up logging for the main script
    migration = SNMPMigration()
    logger = migration.logger
    
    try:
        logger.info("=" * 80)
        logger.info(f"Starting SNMP migration script at {datetime.now()}")
        
        # File paths
        snmpv2_file = "snmpv2_remove.txt"
        snmpv3_file = "snmpv3_add.txt"
        device_list_file = "input_devices.txt"
        
        # Validate files
        required_files = [snmpv2_file, snmpv3_file, device_list_file, migration.snmp_server_hosts_file]
        for file in required_files:
            if not os.path.exists(file):
                logger.error(f"Required file '{file}' not found!")
                return
        
        # Read files
        with open(device_list_file) as f:
            device_list = [line.strip() for line in f if line.strip()]
        
        if not device_list:
            logger.error("No devices found in the input file!")
            return
        
        try:
            username = input("Enter device username: ")
            password = getpass.getpass("Enter device password: ")
            migration.snmpv3_username = input("Enter SNMPv3 username: ")
            
            if not migration.snmpv3_username:
                logger.error("SNMPv3 username cannot be empty!")
                return
            
        except KeyboardInterrupt:
            print("\nScript cancelled by user")
            return
        except Exception as e:
            logger.error(f"Error getting credentials: {str(e)}")
            return
        
        # Process devices
        results = migration.process_devices_parallel(device_list, username, password)
        
        # Final report
        print(f"\n--- Configuration Report ---")
        print(f"Total Devices: {len(device_list)}")
        print(f"Successful Configurations: {sum(1 for d, s in results if s)}")
        print(f"Failed Configurations: {sum(1 for d, s in results if not s)}")
        print("Logs have been written to 'snmp_migration.log'")
        
    except Exception as e:
        logger.error(f"Script failed with error: {str(e)}", exc_info=True)
    finally:
        logger.info(f"Script completed at {datetime.now()}")
        logger.info("=" * 80)

if __name__ == "__main__":
    main()
    