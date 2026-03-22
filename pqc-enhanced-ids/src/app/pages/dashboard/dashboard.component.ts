import { Component } from '@angular/core';
import { NgIf, NgClass } from '@angular/common';
import { Router } from '@angular/router';
import { LucideAngularModule } from 'lucide-angular';

import { ButtonComponent } from '../../components/ui/button/button.component';
import { MetricsPanelComponent } from '../../components/metrics-panel/metrics-panel.component';
import { EventsPanelComponent } from '../../components/events-panel/events-panel.component';
import { QmlModelPanelComponent } from '../../components/qml-model-panel/qml-model-panel.component';
import { ConfigsPanelComponent } from '../../components/configs-panel/configs-panel.component';
import { SettingsPanelComponent } from '../../components/settings-panel/settings-panel.component';

@Component({
  selector: 'app-dashboard',
  imports: [
    NgIf,
    NgClass,
    LucideAngularModule,
    ButtonComponent,
    MetricsPanelComponent,
    EventsPanelComponent,
    QmlModelPanelComponent,
    ConfigsPanelComponent,
    SettingsPanelComponent
  ],
  templateUrl: './dashboard.component.html',
  styleUrl: './dashboard.component.css'
})
export class DashboardComponent {
  activeTab: 'events' | 'qml' | 'configs' | 'settings' = 'events';
  constructor(private router: Router) {}

  setTab(tab: 'events' | 'qml' | 'configs' | 'settings') {
    this.activeTab = tab;
  }

  logout() {
    this.router.navigate(['/']);
  }
}
