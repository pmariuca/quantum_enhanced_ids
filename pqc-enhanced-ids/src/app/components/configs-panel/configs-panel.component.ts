import { Component } from '@angular/core';
import { NgClass, NgIf } from '@angular/common';
import { LucideAngularModule } from 'lucide-angular';

@Component({
  selector: 'app-configs-panel',
  imports: [
    NgIf,
    NgClass,
    LucideAngularModule
  ],
  templateUrl: './configs-panel.component.html',
  styleUrl: './configs-panel.component.css'
})
export class ConfigsPanelComponent {
  activeTab: 'kernel' | 'ebpf' | 'firewall' = 'kernel';
  copied: string | null = null;

  kernelConfig: string = `# Kernel Security Configuration
  # Version: 3.2.1
  # Last Modified: 2026-03-20

  [security.core]
  enabled = true
  strict_mode = true
  audit_level = verbose

  [protection.memory]
  stack_protection = true
  heap_randomization = true
  buffer_overflow_detection = true
  max_allocation_size = 2GB

  [protection.process]
  aslr_enabled = true
  dep_enabled = true
  privilege_escalation_block = true
  suspicious_syscall_monitoring = true

  [network.firewall]
  default_policy = deny
  allow_loopback = true
  rate_limiting = true
  ddos_protection = enabled

  [monitoring.events]
  log_level = debug
  real_time_alerts = true
  event_buffer_size = 10000
  retention_days = 90`;

  ebpfConfig: string = `# eBPF Security Rules
  program syscall_monitor {
    on_syscall_enter {
      if (syscall.type == EXECVE) {
        alert("Suspicious execution", HIGH);
        block_action();
      }
    }
  }`;

  firewallRules: string = `# Firewall Rules Configuration
  table inet filter {
    chain input {
      type filter hook input priority 0; policy drop;

      ct state established,related accept
      iif lo accept
      tcp dport 22 limit rate 3/minute accept

      log prefix "DROPPED: " drop
    }
  }`;

  handleCopy(content: string, name: string) {
    navigator.clipboard.writeText(content);
    this.copied = name;

    setTimeout(() => {
      this.copied = null;
    }, 2000);
  }

  handleSave() {
    console.log("Saved");
  }

  handleReload() {
    console.log("Reloaded");
  }

  handleExport(name: string) {
    console.log("Export", name);
  }
}
