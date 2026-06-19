import { Component, AfterViewInit, OnInit, OnDestroy } from '@angular/core';
import { DecimalPipe, NgFor } from '@angular/common';
import { LucideAngularModule } from 'lucide-angular';
import { Chart } from 'chart.js/auto';
import { MetricsService, Metrics } from '../../services/metrics.service';

@Component({
  selector: 'app-metrics-panel',
  imports: [
    NgFor, 
    DecimalPipe,
    LucideAngularModule
  ],
  templateUrl: './metrics-panel.component.html',
})
export class MetricsPanelComponent implements OnInit, AfterViewInit {
  cpuData: number[] = [];
  memData: number[] = [];
  threatData: number[] = [];
  metrics: Metrics | null = null;
  intervalId: any;
  private viewInitialized = false;
  private cpuChart?: Chart;
  private memChart?: Chart;
  private threatChart?: Chart;

  constructor(private metricsService: MetricsService) {}

  ngOnInit() {
    this.loadMetrics();
    // Poll metrics every 5 seconds
    this.intervalId = setInterval(() => this.loadMetrics(), 5000);
  }

  ngOnDestroy() {
    if (this.intervalId) {
      clearInterval(this.intervalId);
    }
  }

  private loadMetrics() {
    this.metricsService.getMetrics().subscribe({
      next: (m) => {
        this.metrics = m;
        this.cpuData = [...this.cpuData, m.cpu_pct].slice(-10);
        this.memData = [...this.memData, m.mem_pct].slice(-10);
        this.threatData = [...this.threatData, m.total_deny].slice(-10);
        this.updateCharts();
      },
      error: (err) => console.error('Failed to load metrics:', err)
    });
  }

  private updateCharts() {
    if (!this.viewInitialized) {
      return;
    }

    this.cpuChart = this.upsertChart(this.cpuChart, 'cpuChart', this.cpuData, '#d946ef', true);
    this.memChart = this.upsertChart(this.memChart, 'memChart', this.memData, '#8b5cf6', true);
    this.threatChart = this.upsertChart(this.threatChart, 'threatChart', this.threatData, '#ff006e', true);
  }

  ngAfterViewInit() {
    this.viewInitialized = true;
    this.updateCharts();
  }

  hexToRgba(hex: string, alpha: number) {
    const r = parseInt(hex.slice(1, 3), 16);
    const g = parseInt(hex.slice(3, 5), 16);
    const b = parseInt(hex.slice(5, 7), 16);
    return `rgba(${r}, ${g}, ${b}, ${alpha})`;
  }

  private upsertChart(existing: Chart | undefined, id: string, data: number[], color: string, fill = false): Chart | undefined {
    const canvas = document.getElementById(id) as HTMLCanvasElement;
    if (!canvas) {
      console.warn(`[MetricsPanel] canvas not found: ${id}`);
      return existing;
    }

    if (existing) {
      existing.data.labels = data.map((_, i) => i);
      if (existing.data.datasets[0]) {
        existing.data.datasets[0].data = data;
      }
      existing.update();
      return existing;
    }
    
    const ctx = canvas.getContext('2d')!;
    let background: string | CanvasGradient = 'transparent';

    if (fill) {
      const gradient = ctx.createLinearGradient(0, 0, 0, 120);
      gradient.addColorStop(0, this.hexToRgba(color, 0.4));
      gradient.addColorStop(1, this.hexToRgba(color, 0));
      background = gradient;
    }

    return new Chart(id, {
      type: fill ? 'line' : 'line',
      data: {
        labels: data.map((_, i) => i),
        datasets: [{
          data,
          tension: 0.35,
          borderWidth: 2,
          borderColor: color,
          backgroundColor: fill ? background : 'transparent',
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

  calculateSystemHealth(): number {
    if (!this.metrics) return 0;

    // Weighted formula:
    // 60% based on CPU + Memory usage
    // 40% based on threat ratio (fewer blocks = better)
    
    const resourceHealth = 100 - ((this.metrics.cpu_pct + this.metrics.mem_pct) / 2);
    
    const threatRatio = this.metrics.total_events > 0 
      ? (this.metrics.total_deny / this.metrics.total_events) * 100 
      : 0;
    const threatHealth = Math.max(0, 100 - threatRatio);
    
    return Math.round((resourceHealth * 0.6 + threatHealth * 0.4) * 10) / 10;
  }

  getHealthStatus(): string {
    const health = this.calculateSystemHealth();
    if (health >= 90) return 'Optimal';
    if (health >= 70) return 'Good';
    if (health >= 50) return 'Fair';
    return 'Poor';
  }

  getThreatTrend(): { value: number; isUp: boolean } {
    if (this.threatData.length < 2) return { value: 0, isUp: false };
    
    const current = this.threatData[this.threatData.length - 1];
    const previous = this.threatData[this.threatData.length - 2];
    const change = current - previous;
    
    return {
      value: Math.abs(change),
      isUp: change > 0
    };
  }

  getMemoryTrend(): { value: number; isUp: boolean } {
    if (this.memData.length < 2) {
      return { value: 0, isUp: false };
    }

    const current = this.memData[this.memData.length - 1];
    const previous = this.memData[this.memData.length - 2];

    if (previous <= 0) {
      return { value: current > 0 ? 100 : 0, isUp: current > 0 };
    }

    const changePct = Math.abs(((current - previous) / previous) * 100);
    return {
      value: Math.round(changePct * 10) / 10,
      isUp: current > previous,
    };
  }
}