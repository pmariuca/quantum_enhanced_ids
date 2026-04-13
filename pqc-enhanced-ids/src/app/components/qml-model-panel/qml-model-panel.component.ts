import { Component, AfterViewInit, OnInit } from '@angular/core';
import { NgFor } from '@angular/common';
import { LucideAngularModule } from 'lucide-angular';
import { Chart } from 'chart.js/auto';

import { BadgeComponent } from '../ui/badge/badge.component';
import { ProgressComponent } from '../ui/progress/progress.component';
import { ModelService, ModelActivity, ModelMetrics } from '../../services/model.service';

@Component({
  selector: 'app-qml-model-panel',
  imports: [
    NgFor, 
    LucideAngularModule, 
    BadgeComponent, 
    ProgressComponent],
  templateUrl: './qml-model-panel.component.html',
})
export class QmlModelPanelComponent implements OnInit, AfterViewInit {
  monitoringData = [
    { name: "00:00", syscalls: 2400, packets: 1800, latency: 45 },
    { name: "04:00", syscalls: 1800, packets: 1200, latency: 38 },
    { name: "08:00", syscalls: 3200, packets: 2800, latency: 52 },
    { name: "12:00", syscalls: 4100, packets: 3500, latency: 48 },
    { name: "16:00", syscalls: 3800, packets: 3200, latency: 43 },
    { name: "20:00", syscalls: 2900, packets: 2100, latency: 41 }
  ];

  modelMetrics: any[] = [];
  recentSyscalls: any[] = [];
  recentPackets: any[] = [];

  constructor(private modelService: ModelService) {}

  ngOnInit() {
    this.loadData();
  }

  private loadData() {
    this.modelService.getMetrics().subscribe({
      next: (m) => {
        this.modelMetrics = [
          { name: "Threat Detection", value: 99.2 },
          { name: "False Positive Rate", value: m.ml_coverage },
          { name: "Deny Rate", value: m.deny_rate },
          { name: "Model Coverage", value: m.ml_coverage }
        ];
      },
      error: (err) => console.error('Failed to load model metrics:', err)
    });

    this.modelService.getActivity().subscribe({
      next: (activity) => {
        this.recentSyscalls = activity.recent_syscalls.slice(0, 4);
        this.recentPackets = activity.recent_packets.slice(0, 4);
      },
      error: (err) => console.error('Failed to load model activity:', err)
    });
  }

  ngAfterViewInit() {
    const ctx = document.getElementById('chart') as HTMLCanvasElement;
    if (!ctx) return;

    new Chart(ctx, {
      type: 'line',
      data: {
        labels: this.monitoringData.map(d => d.name),
        datasets: [
          {
            label: 'Syscalls',
            data: this.monitoringData.map(d => d.syscalls),
            borderColor: '#d946ef',
            tension: 0.4,
            borderWidth: 2,
            pointRadius: 3
          },
          {
            label: 'Packets',
            data: this.monitoringData.map(d => d.packets),
            borderColor: '#06b6d4',
            tension: 0.4,
            borderWidth: 2,
            pointRadius: 3
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: true } },
        scales: {
          y: { beginAtZero: true }
        }
      }
    });
  }
}