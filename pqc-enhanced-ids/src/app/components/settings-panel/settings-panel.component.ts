import { Component } from '@angular/core';
import { NgIf } from '@angular/common';
import { FormsModule } from '@angular/forms';
import { LucideAngularModule } from 'lucide-angular';

import { SwitchComponent } from '../ui/switch/switch.component';
import { LabelComponent } from '../ui/label/label.component';
import { SliderComponent } from '../ui/slider/slider.component';
import { SelectComponent } from '../ui/select/select.component';
import { ButtonComponent } from '../ui/button/button.component';
import { SeparatorComponent } from '../ui/separator/separator.component';

@Component({
  selector: 'app-settings-panel',
  standalone: true,
  imports: [
    NgIf,
    FormsModule,
    LucideAngularModule,
    SwitchComponent,
    LabelComponent,
    SliderComponent,
    SelectComponent,
    ButtonComponent,
    SeparatorComponent
  ],
  templateUrl: './settings-panel.component.html',
})
export class SettingsPanelComponent {
  settings = {
    realtimeMonitoring: true,
    autoBlock: true,
    strictMode: false,
    kernelHardening: true,
    networkMonitoring: true,
    memoryProtection: true,
    syscallFiltering: true,
    anomalyDetection: true,
    alertNotifications: true,
    auditLogging: true,
    threatIntelligence: true,
    autoUpdates: false,

    memoryAslr: true,
    memoryDep: true,
    memoryStackCanary: true,
    memoryHeapProtection: false,

    syscallWhitelisting: true,
    syscallAudit: true,
    syscallRateLimit: false,
    syscallSeccomp: true,
  };

  sensitivity = 75;
  retentionDays = 90;
  logLevel = '';
  signatureType = 'rsa-2048';

  expandedSections = {
    memory: false,
    syscall: false
  };

  toggle(key: keyof typeof this.settings) {
    this.settings[key] = !this.settings[key];
  }

  toggleSection(section: 'memory' | 'syscall') {
    this.expandedSections[section] = !this.expandedSections[section];
  }

  apply() {
    console.log('apply settings', this.settings);
  }

  reset() {
    console.log('reset');
  }
}