import { Component, AfterViewInit, OnInit } from '@angular/core';
import { NgFor } from '@angular/common';
import { LucideAngularModule } from 'lucide-angular';
import { Chart } from 'chart.js/auto';

import { BadgeComponent } from '../ui/badge/badge.component';
import { ProgressComponent } from '../ui/progress/progress.component';
import { ModelService, ModelActivity, ModelMetrics, SecurityEvent, TimeseriesBucket } from '../../services/model.service';

interface DisplaySyscall {
  name: string;
  pid: number;
  status: string;
  path: string;
  timestamp: string;
}

interface DisplayPacket {
  protocol: string;
  size: string;
  status: string;
  source: string;
  dest: string;
  timestamp: string;
}

const PROTOCOL_MAP: Record<number, string> = { 1: 'ICMP', 6: 'TCP', 17: 'UDP' };

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
  metrics: ModelMetrics | null = null;

  get totalAnalysis(): string {
    if (!this.metrics) return '—';
    const n = this.metrics.total_events;
    return n >= 1000 ? (n / 1000).toFixed(1) + 'K' : n.toString();
  }

  get modelAccuracy(): string {
    if (!this.metrics) return '—';
    return ((1 - this.metrics.avg_ml_prob) * 100).toFixed(1);
  }

  modelMetrics: any[] = [];
  recentSyscalls: DisplaySyscall[] = [];
  recentPackets: DisplayPacket[] = [];

  private mapSyscall(ev: SecurityEvent): DisplaySyscall {
    return {
      name: ev.exec?.path?.split('/').pop() ?? ev.reason,
      pid: ev.exec?.pid ?? 0,
      status: ev.policy === 'DENY' ? 'blocked' : 'allowed',
      path: ev.exec?.path ?? '',
      timestamp: ev.ts_daemon,
    };
  }

  private mapPacket(ev: SecurityEvent): DisplayPacket {
    const pkt = ev.packet ?? ev.packet_in;
    const proto = pkt ? (PROTOCOL_MAP[pkt.protocol] ?? `proto:${pkt.protocol}`) : '?';
    return {
      protocol: proto,
      size: pkt ? `${pkt.len}B` : '?',
      status: ev.policy === 'DENY' ? 'blocked' : 'allowed',
      source: pkt ? `${pkt.src_ip}:${pkt.src_port}` : '',
      dest: pkt ? `${pkt.dst_ip}:${pkt.dst_port}` : '',
      timestamp: ev.ts_daemon,
    };
  }

  private chart: Chart | null = null;

  constructor(private modelService: ModelService) {}

  ngOnInit() {
    this.loadData();
  }

  private loadData() {
    this.modelService.getMetrics().subscribe({
      next: (m) => {
        this.metrics = m;
        this.modelMetrics = [
          { name: "Threat Detection", value: +((1 - m.avg_ml_prob) * 100).toFixed(1) },
          { name: "False Positive Rate", value: m.ml_coverage },
          { name: "Deny Rate", value: m.deny_rate },
          { name: "Model Coverage", value: m.ml_coverage }
        ];
      },
      error: (err) => console.error('Failed to load model metrics:', err)
    });

    this.modelService.getActivity().subscribe({
      next: (activity) => {
        this.recentSyscalls = activity.recent_syscalls.slice(0, 4).map(ev => this.mapSyscall(ev));
        this.recentPackets = activity.recent_packets.slice(0, 4).map(ev => this.mapPacket(ev));
      },
      error: (err) => console.error('Failed to load model activity:', err)
    });

    this.modelService.getTimeseries().subscribe({
      next: (buckets) => this.renderChart(buckets),
      error: (err) => console.error('Failed to load timeseries:', err)
    });
  }

  ngAfterViewInit() {
    // Chart will be rendered once timeseries data arrives via loadData()
  }

  private renderChart(buckets: TimeseriesBucket[]) {
    const ctx = document.getElementById('chart') as HTMLCanvasElement;
    if (!ctx) return;

    if (this.chart) {
      this.chart.destroy();
    }

    this.chart = new Chart(ctx, {
      type: 'line',
      data: {
        labels: buckets.map(b => b.label),
        datasets: [
          {
            label: 'Execs',
            data: buckets.map(b => b.execs),
            borderColor: '#d946ef',
            tension: 0.4,
            borderWidth: 2,
            pointRadius: 3
          },
          {
            label: 'Packets',
            data: buckets.map(b => b.packets),
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