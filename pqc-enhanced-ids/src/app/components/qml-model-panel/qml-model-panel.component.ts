import { Component, AfterViewInit } from '@angular/core';
import { NgFor } from '@angular/common';
import { LucideAngularModule } from 'lucide-angular';
import { Chart } from 'chart.js/auto';

import { BadgeComponent } from '../ui/badge/badge.component';
import { ProgressComponent } from '../ui/progress/progress.component';

interface Syscall {
  id: number;
  name: string;
  pid: number;
  path: string;
  status: string;
  timestamp: string;
}

interface Packet {
  id: number;
  protocol: string;
  source: string;
  dest: string;
  size: string;
  status: string;
}

@Component({
  selector: 'app-qml-model-panel',
  imports: [
    NgFor, 
    LucideAngularModule, 
    BadgeComponent, 
    ProgressComponent],
  templateUrl: './qml-model-panel.component.html',
})
export class QmlModelPanelComponent implements AfterViewInit {
  monitoringData = [
    { name: "00:00", syscalls: 2400, packets: 1800, latency: 45 },
    { name: "04:00", syscalls: 1800, packets: 1200, latency: 38 },
    { name: "08:00", syscalls: 3200, packets: 2800, latency: 52 },
    { name: "12:00", syscalls: 4100, packets: 3500, latency: 48 },
    { name: "16:00", syscalls: 3800, packets: 3200, latency: 43 },
    { name: "20:00", syscalls: 2900, packets: 2100, latency: 41 }
  ];

  modelMetrics = [
    { name: "Threat Detection", value: 99.2 },
    { name: "False Positive Rate", value: 0.3 },
    { name: "Response Time", value: 95.8 },
    { name: "Model Accuracy", value: 98.7 }
  ];

  recentSyscalls: Syscall[] = [
    { id: 1, name: "execve", pid: 4521, path: "/usr/bin/python3", status: "blocked", timestamp: "14:32:15" },
    { id: 2, name: "open", pid: 3289, path: "/etc/shadow", status: "allowed", timestamp: "14:31:58" },
    { id: 3, name: "fork", pid: 2156, path: "-", status: "allowed", timestamp: "14:31:42" },
    { id: 4, name: "setuid", pid: 4521, path: "-", status: "blocked", timestamp: "14:31:20" }
  ];

  recentPackets: Packet[] = [
    { id: 1, protocol: "TCP", source: "192.168.1.45:8080", dest: "10.0.0.3:443", size: "1.2 KB", status: "allowed" },
    { id: 2, protocol: "UDP", source: "192.168.1.12:53", dest: "8.8.8.8:53", size: "512 B", status: "allowed" },
    { id: 3, protocol: "ICMP", source: "192.168.1.99", dest: "192.168.1.1", size: "84 B", status: "blocked" },
    { id: 4, protocol: "TCP", source: "10.0.0.45:22", dest: "192.168.1.10:2222", size: "2.4 KB", status: "allowed" }
  ];

  ngAfterViewInit() {
    const ctx = document.getElementById('chart') as HTMLCanvasElement;

    const verticalLinePlugin = {
      id: 'verticalLine',
      afterDraw: (chart: any) => {
        if (chart.tooltip?._active?.length) {
          const ctx = chart.ctx;
          const x = chart.tooltip._active[0].element.x;
          const topY = chart.scales.y.top;
          const bottomY = chart.scales.y.bottom;

          ctx.save();
          ctx.beginPath();
          ctx.moveTo(x, topY);
          ctx.lineTo(x, bottomY);
          ctx.lineWidth = 1;
          ctx.strokeStyle = 'rgba(255,255,255,0.2)';
          ctx.stroke();
          ctx.restore();
        }
      }
    };

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
          },
          {
            label: 'Latency (ms)',
            data: this.monitoringData.map(d => d.latency),
            borderColor: '#8b5cf6',
            tension: 0.4,
            borderWidth: 2,
            pointRadius: 3,
            yAxisID: 'y1' // 👈 IMPORTANT
          }
        ]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,

        interaction: {
          mode: 'index',
          intersect: false
        },

        plugins: {
          legend: {
            position: 'bottom',
            labels: {
              color: '#a0a0c0',
              usePointStyle: true,
              pointStyle: 'circle',
              boxWidth: 8,
              boxHeight: 8,
              padding: 15
            }
          },
          tooltip: {
            enabled: true,
            backgroundColor: 'rgba(15,15,30,0.95)',
            borderColor: 'rgba(139,92,246,0.3)',
            borderWidth: 1,
            padding: 10,
            titleColor: '#e0e0ff',
            bodyColor: '#e0e0ff',
            displayColors: false
          }
        },

        scales: {
          x: {
            ticks: { color: '#a0a0c0' },
            grid: {
              color: 'rgba(139,92,246,0.1)'
            }
          },
          y: {
            ticks: { color: '#a0a0c0' },
            grid: {
              color: 'rgba(139,92,246,0.1)'
            }
          },
          y1: {
            position: 'right',
            display: false // keeps layout clean
          }
        }
      },
      plugins: [verticalLinePlugin]
    });
  }
}