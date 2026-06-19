import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';

@Injectable({
  providedIn: 'root'
})
export class PolicyService {
  private apiUrl = `${environment.apiUrl}/policy`;

  constructor(private http: HttpClient) {}

  getPolicy(): Observable<any> {
    return this.http.get(`${this.apiUrl}`, { responseType: 'text' });
  }

  updatePolicy(content: string): Observable<{ status: string }> {
    return this.http.put<{ status: string }>(this.apiUrl, content, {
      headers: { 'Content-Type': 'application/json' }
    });
  }

  getPolicyLocal(): Observable<any> {
    return this.http.get(`${this.apiUrl}/local`, { responseType: 'text' });
  }

  updatePolicyLocal(content: string): Observable<{ status: string }> {
    return this.http.put<{ status: string }>(`${this.apiUrl}/local`, content, {
      headers: { 'Content-Type': 'application/json' }
    });
  }
}