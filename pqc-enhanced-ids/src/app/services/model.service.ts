import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';

export interface ModelMetrics {
  total_events: number;
  deny_rate: number;
  ml_coverage: number;
  avg_ml_prob: number;
}

export interface ExecBlock {
  pid: number;
  ppid: number;
  uid: number;
  path: string;
}

export interface PacketBlock {
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: number;
  len: number;
}

export interface SecurityEvent {
  ts_daemon: string;
  event_id: number;
  type: string;
  policy: string;
  reason: string;
  ml_prob?: number;
  exec?: ExecBlock;
  packet?: PacketBlock;
  packet_in?: PacketBlock;
  [key: string]: any;
}

export interface ModelActivity {
  recent_syscalls: SecurityEvent[];
  recent_packets: SecurityEvent[];
}

export interface TimeseriesBucket {
  label: string;
  execs: number;
  packets: number;
}

@Injectable({
  providedIn: 'root'
})
export class ModelService {
  private apiUrl = `${environment.apiUrl}/model`;

  constructor(private http: HttpClient) {}

  getMetrics(): Observable<ModelMetrics> {
    return this.http.get<ModelMetrics>(`${this.apiUrl}/metrics`);
  }

  getActivity(): Observable<ModelActivity> {
    return this.http.get<ModelActivity>(`${this.apiUrl}/activity`);
  }

  getTimeseries(): Observable<TimeseriesBucket[]> {
    return this.http.get<TimeseriesBucket[]>(`${this.apiUrl}/timeseries`);
  }
}