import { Component } from '@angular/core';
import { NgFor, NgClass } from '@angular/common';
import { LucideAngularModule } from 'lucide-angular';

import { BadgeComponent } from '../ui/badge/badge.component';
import { ScrollAreaComponent } from '../ui/scroll-area/scroll-area.component';
import { SelectComponent } from '../ui/select/select.component';

type EventType = 'critical' | 'warning' | 'success' | 'info';

interface SecurityEvent {
  id: string;
  type: EventType;
  title: string;
  description: string;
  timestamp: string;
  source: string;
}

@Component({
  selector: 'app-events-panel',
  imports: [
    NgFor, 
    NgClass, 
    LucideAngularModule,
    BadgeComponent,
    ScrollAreaComponent,
    SelectComponent
  ],
  templateUrl: './events-panel.component.html',
  styleUrl: './events-panel.component.css'
})
export class EventsPanelComponent {
  events: SecurityEvent[] = [];
  filter: EventType | 'all' = 'all';
  logSource = 'both';

  intervalId: any;

  eventTypeConfig: any = {
    critical: {
      icon: 'x-circle',
      color: 'text-destructive',
      bg: 'bg-[#ff006e]/10',
      border: 'border-[#ff006e]/30',
      badge: 'bg-[#ff006e]/20 text-[#ff006e]',
      label: 'BLOCKED'
    },
    warning: {
      icon: 'alert-triangle',
      color: 'text-yellow-400',
      bg: 'bg-yellow-400/10',
      border: 'border-yellow-400/30',
      badge: 'bg-yellow-400/20 text-yellow-400',
      label: 'ML CHECK'
    },
    success: {
      icon: 'shield-check',
      color: 'text-accent',
      bg: 'bg-[#06b6d4]/10',
      border: 'border-[#06b6d4]/30',
      badge: 'bg-[#06b6d4]/20 text-[#06b6d4]',
      label: 'OK'
    },
    info: {
      icon: 'info',
      color: 'text-secondary',
      bg: 'bg-[#8b5cf6]/10',
      border: 'border-[#8b5cf6]/30',
      badge: 'bg-[#8b5cf6]/20 text-[#8b5cf6]',
      label: 'INFO'
    }
  };

  ngOnInit() {
    this.events = this.generateMockEvents();

    this.intervalId = setInterval(() => {
      const newEvent = this.generateRandomEvent();
      this.events = [newEvent, ...this.events].slice(0, 20);
    }, 8000);
  }

  ngOnDestroy() {
    clearInterval(this.intervalId);
  }

  generateMockEvents(): SecurityEvent[] {
    return [
      {
        id: '1',
        type: 'critical',
        title: 'Unauthorized kernel module load attempt',
        description: 'Detected attempt to load unsigned kernel module',
        timestamp: '2026-03-20 14:32:15',
        source: 'Kernel Monitor'
      }
    ];
  }

  generateRandomEvent(): SecurityEvent {
    const types: EventType[] = ['critical', 'warning', 'success', 'info'];

    return {
      id: Date.now().toString(),
      type: types[Math.floor(Math.random() * 4)],
      title: 'New security event detected',
      description: 'Real-time monitoring detected a new event',
      timestamp: new Date().toLocaleString(),
      source: 'Kernel Monitor'
    };
  }

  get filteredEvents() {
    return this.filter === 'all'
      ? this.events
      : this.events.filter(e => e.type === this.filter);
  }

  setFilter(type: any) {
    this.filter = type;
  }

  downloadLogs() {
    const content = JSON.stringify(this.filteredEvents, null, 2);
    const blob = new Blob([content], { type: 'text/plain' });

    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'logs.txt';
    link.click();
  }
}
