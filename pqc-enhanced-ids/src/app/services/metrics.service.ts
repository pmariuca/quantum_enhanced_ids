import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';

export interface Metrics {
  cpu_pct: number;
  mem_pct: number;
  mem_total_mb: number;
  mem_used_mb: number;
  total_events: number;
  total_allow: number;
  total_deny: number;
  total_ml: number;
}

@Injectable({
  providedIn: 'root'
})
export class MetricsService {
  private apiUrl = `${environment.apiUrl}/metrics`;

  constructor(private http: HttpClient) {}

  getMetrics(): Observable<Metrics> {
    return this.http.get<Metrics>(this.apiUrl);
  }
}