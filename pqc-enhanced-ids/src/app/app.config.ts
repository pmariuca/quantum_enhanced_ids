import { ApplicationConfig, provideZoneChangeDetection, importProvidersFrom } from '@angular/core';
import { provideRouter } from '@angular/router';
import { provideHttpClient } from '@angular/common/http';
import { HTTP_INTERCEPTORS } from '@angular/common/http';
import { AuthInterceptor } from './interceptors/auth.interceptor';

import { routes } from './app.routes';
import { 
  LucideAngularModule, Shield, Eye, Cpu, Network, Lock, ShieldAlert, Check, ChevronDown, RefreshCw, Save, FileCode, Download, CheckIcon, Copy, HardDrive, Activity, TrendingUp, TrendingDown, LogOut, Database, Settings, Clock,
  XCircle, AlertTriangle, ShieldCheck, Zap, Brain, ChevronRight, Info, Bell
 } from 'lucide-angular';

export const appConfig: ApplicationConfig = {
  providers: [
    provideZoneChangeDetection({ eventCoalescing: true }), 
    provideRouter(routes),
    provideHttpClient(),
    importProvidersFrom(
      LucideAngularModule.pick({ 
        Shield, Eye, Cpu, Network, Lock, ShieldAlert, Check, ChevronDown, RefreshCw, Save, FileCode, Download, CheckIcon, Copy, HardDrive, Activity, TrendingUp, TrendingDown, LogOut, Database, Settings, Clock,
        XCircle, AlertTriangle, ShieldCheck, Zap, Brain, ChevronRight, Info, Bell
      })
    ),
    {
      provide: HTTP_INTERCEPTORS,
      useClass: AuthInterceptor,
      multi: true
    }
  ]
};