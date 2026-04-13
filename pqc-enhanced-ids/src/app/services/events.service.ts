import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';

export interface SecurityEvent {
  ts_daemon: string;
  event_id: number;
  type: string;
  policy: string;
  reason: string;
  ml_prob?: number;
}

@Injectable({
  providedIn: 'root'
})
export class EventsService {
  private apiUrl = `${environment.apiUrl}/events`;

  constructor(private http: HttpClient) {}

  getEvents(limit = 50, type = '', policy = ''): Observable<SecurityEvent[]> {
    let url = `${this.apiUrl}?limit=${limit}`;
    if (type) url += `&type=${type}`;
    if (policy) url += `&policy=${policy}`;
    return this.http.get<SecurityEvent[]>(url);
  }

  getEventsStream(token: string): EventSource {
    return new EventSource(`${this.apiUrl}/stream?token=${encodeURIComponent(token)}`);
  }
}