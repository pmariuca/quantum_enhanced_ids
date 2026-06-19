import { Component, OnInit } from '@angular/core';
import { NgClass, NgIf } from '@angular/common';
import { LucideAngularModule } from 'lucide-angular';
import { PolicyService } from '../../services/policy.service';

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
export class ConfigsPanelComponent implements OnInit {
  activeTab: 'kernel' | 'ebpf' | 'firewall' = 'kernel';
  copied: string | null = null;

  kernelConfig: string = '';
  ebpfConfig: string = '';
  firewallRules: string = '';
  saving = false;
  saveMessage = '';

  constructor(private policyService: PolicyService) {}

  ngOnInit() {
    this.loadPolicy();
  }

  private loadPolicy() {
    this.policyService.getPolicy().subscribe({
      next: (content) => {
        this.kernelConfig = content;
      },
      error: (err) => console.error('Failed to load policy:', err)
    });

    this.policyService.getPolicyLocal().subscribe({
      next: (content) => {
        this.ebpfConfig = content;
      },
      error: (err) => console.error('Failed to load policy local:', err)
    });
  }

  handleCopy(content: string, name: string) {
    navigator.clipboard.writeText(content);
    this.copied = name;

    setTimeout(() => {
      this.copied = null;
    }, 2000);
  }

  handleSave() {
    this.saving = true;
    this.saveMessage = '';

    const promises: Promise<void>[] = [];

    if (this.kernelConfig) {
      promises.push(
        new Promise((resolve, reject) => {
          this.policyService.updatePolicy(this.kernelConfig).subscribe({
            next: () => resolve(),
            error: (err) => reject(err)
          });
        })
      );
    }

    if (this.ebpfConfig) {
      promises.push(
        new Promise((resolve, reject) => {
          this.policyService.updatePolicyLocal(this.ebpfConfig).subscribe({
            next: () => resolve(),
            error: (err) => reject(err)
          });
        })
      );
    }

    Promise.all(promises)
      .then(() => {
        this.saveMessage = 'Policy saved successfully!';
      })
      .catch((err) => {
        this.saveMessage = 'Failed to save policy';
        console.error(err);
      })
      .finally(() => {
        this.saving = false;
      });
  }

  handleReload() {
    this.loadPolicy();
  }

  handleExport(name: string) {
    const content = this.activeTab === 'kernel' ? this.kernelConfig : this.ebpfConfig;
    const blob = new Blob([content], { type: 'application/json' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `${name}-policy.json`;
    link.click();
  }
}