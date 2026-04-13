import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { Observable } from 'rxjs';
import { environment } from '../../environments/environment';

@Injectable({
  providedIn: 'root'
})
export class AuthService {
  private apiUrl = `${environment.apiUrl}/auth`;

  constructor(private http: HttpClient) {}

  login(username: string, password: string): Observable<{ token: string }> {
    return this.http.post<{ token: string }>(`${this.apiUrl}/login`, {
      username,
      password
    });
  }

  refreshToken(): Observable<{ token: string }> {
    const token = this.getToken();
    if (!token) {
      throw new Error('No token to refresh');
    }
    return this.http.post<{ token: string }>(`${this.apiUrl}/refresh`, {
      token
    });
  }

  getToken(): string | null {
    return localStorage.getItem('token');
  }

  setToken(token: string): void {
    localStorage.setItem('token', token);
  }

  clearToken(): void {
    localStorage.removeItem('token');
  }

  isAuthenticated(): boolean {
    return !!this.getToken();
  }

  isTokenExpired(): boolean {
    const token = this.getToken();
    if (!token) return true;

    try {
      const parts = token.split('.');
      if (parts.length !== 3) return true;

      const decoded = JSON.parse(atob(parts[1]));
      const currentTime = Math.floor(Date.now() / 1000);
      // Consider token expired if it expires within 5 minutes
      return decoded.exp - currentTime < 300;
    } catch {
      return true;
    }
  }
}