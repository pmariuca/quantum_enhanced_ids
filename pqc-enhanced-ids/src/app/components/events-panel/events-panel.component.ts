import { Component, OnInit, OnDestroy } from '@angular/core';
import { NgFor, NgClass } from '@angular/common';
import { LucideAngularModule } from 'lucide-angular';

import { BadgeComponent } from '../ui/badge/badge.component';
import { ScrollAreaComponent } from '../ui/scroll-area/scroll-area.component';
import { SelectComponent } from '../ui/select/select.component';
import { EventsService, SecurityEvent } from '../../services/events.service';
import { AuthService } from '../../services/auth.service';

type EventType = 'critical' | 'warning' | 'success' | 'info';

interface DisplayEvent {
  id: string;
  types: EventType[];
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
export class EventsPanelComponent implements OnInit, OnDestroy {
  events: DisplayEvent[] = [];
  filter: EventType | 'all' = 'all';
  logSource = 'daemon';
  eventSource: EventSource | null = null;

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

  constructor(private eventsService: EventsService, private authService: AuthService) {}

  ngOnInit() {
    this.loadInitialEvents();
    this.subscribeToStream();
  }

  ngOnDestroy() {
    if (this.eventSource) {
      this.eventSource.close();
    }
  }

  private loadInitialEvents() {
    this.eventsService.getEvents(20).subscribe({
      next: (events) => {
        this.events = events
          .reverse()
          .map(ev => this.convertToDisplayEvent(ev));
      },
      error: (err) => console.error('Failed to load events:', err)
    });
  }

  private subscribeToStream() {
    try {
      this.eventSource = this.eventsService.getEventsStream(this.authService.getToken() ?? '');
      this.eventSource.onmessage = (event: any) => {
        const line = event.data;
        const parsed = JSON.parse(line) as SecurityEvent;
        const displayEvent = this.convertToDisplayEvent(parsed);
        this.events = [displayEvent, ...this.events].slice(0, 20);
      };
    } catch (err) {
      console.error('Failed to subscribe to event stream:', err);
    }
  }

  private convertToDisplayEvent(ev: SecurityEvent): DisplayEvent {
    const types: EventType[] = [];
    const isMlAnomalous = ev.ml_prob !== undefined && ev.ml_prob > 0.5;
    
    if (ev.policy === 'DENY') {
      types.push('critical');
    }
    if (isMlAnomalous) {
      types.push('warning');
    }
    if (ev.policy === 'ALLOW' && !isMlAnomalous) {
      types.push('success');
    }
    if (types.length === 0) {
      types.push('info');
    }

    const mlNote = isMlAnomalous 
      ? ` [ML: ${(ev.ml_prob! * 100).toFixed(1)}%]` 
      : '';

    return {
      id: ev.event_id.toString(),
      types,
      title: `${ev.type} event (ID: ${ev.event_id})`,
      description: `Policy: ${ev.policy}, Reason: ${ev.reason}${mlNote}`,
      timestamp: ev.ts_daemon,
      source: 'Kernel Monitor'
    };
  }

  get filteredEvents() {
    return this.filter === 'all'
      ? this.events
      : this.events.filter(e => e.types.includes(this.filter as EventType));
  }

  getDisplayType(event: DisplayEvent): EventType {
    // If filter matches a type in the event, use that for styling
    if (this.filter !== 'all' && event.types.includes(this.filter as EventType)) {
      return this.filter as EventType;
    }
    // Otherwise use primary type
    return event.types[0];
  }

  setFilter(type: any) {
    this.filter = type;
  }

  downloadLogs() {
    if (this.logSource === 'daemon') {
      this.eventsService.downloadEventsFile(this.logSource).subscribe({
        next: (blob) => {
          const link = document.createElement('a');
          link.href = URL.createObjectURL(blob);
          link.download = 'events.jsonl';
          link.click();
          URL.revokeObjectURL(link.href);
        },
        error: (err) => {
          console.error('Failed to download daemon events file, falling back to filtered events:', err);
          this.downloadFilteredEvents();
        }
      });
      return;
    }

    // Kernel source does not have a dedicated backend file export.
    this.downloadFilteredEvents();
  }

  private downloadFilteredEvents() {
    const content = JSON.stringify(this.filteredEvents, null, 2);
    const blob = new Blob([content], { type: 'application/json' });

    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'logs.json';
    link.click();
    URL.revokeObjectURL(link.href);
  }
}