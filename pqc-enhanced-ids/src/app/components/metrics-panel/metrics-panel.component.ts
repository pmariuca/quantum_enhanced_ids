import { Component, AfterViewInit } from '@angular/core';
import { NgFor } from '@angular/common';
import { LucideAngularModule } from 'lucide-angular';
import { Chart } from 'chart.js/auto';

@Component({
  selector: 'app-metrics-panel',
  imports: [
    NgFor, 
    LucideAngularModule
  ],
  templateUrl: './metrics-panel.component.html',
})
export class MetricsPanelComponent implements AfterViewInit {
  cpuData = [45, 52, 48, 65, 58, 70, 63, 55, 61, 68];
  threatData = [12, 8, 15, 9, 6, 11, 7, 5, 9, 4];

  ngAfterViewInit() {
    this.createChart('cpuChart', this.cpuData, '#d946ef');
    this.createChart('memChart', this.cpuData, '#8b5cf6', true);
    this.createChart('threatChart', this.threatData, '#ff006e');
  }

  hexToRgba(hex: string, alpha: number) {
    const r = parseInt(hex.slice(1, 3), 16);
    const g = parseInt(hex.slice(3, 5), 16);
    const b = parseInt(hex.slice(5, 7), 16);

    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
  }

  createChart(id: string, data: number[], color: string, fill = false) {
    const canvas = document.getElementById(id) as HTMLCanvasElement;
    const ctx = canvas.getContext('2d')!;
    let background: string | CanvasGradient = 'transparent';

    if (fill) {
      const gradient = ctx.createLinearGradient(0, 0, 0, 120);

      gradient.addColorStop(0, this.hexToRgba(color, 0.4));
      gradient.addColorStop(1, this.hexToRgba(color, 0));

      background = gradient;
    }

    new Chart(id, {
      type: fill ? 'line' : 'line',
      data: {
        labels: data.map((_, i) => i),
        datasets: [{
          data,
          tension: 0.35,
          borderWidth: 2,
          borderColor: color,
          backgroundColor: fill ? color : 'transparent',
          fill,
          pointRadius: 0,
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { display: false },
          y: { display: false }
        }
      }
    });
  }
}