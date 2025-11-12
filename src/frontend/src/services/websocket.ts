// WebSocket Manager for real-time updates and notifications
import React from 'react';
import { toast } from 'react-hot-toast';

export interface WebSocketMessage {
  type: string;
  payload: any;
  timestamp?: string;
}

export interface NotificationPayload {
  type: 'error' | 'success' | 'info' | 'warning';
  message: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
  title?: string;
}

export interface AlertPayload {
  id: string;
  title: string;
  severity: string;
  description?: string;
}

export interface DashboardStatsPayload {
  totalAlerts: number;
  totalFindings: number;
  criticalAlerts: number;
  recentScans: number;
}

export interface ScanPayload {
  integration_name: string;
  status: 'complete' | 'failed';
  error?: string;
}

export class WebSocketManager {
  private ws: WebSocket | null = null;
  private url: string;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private isConnecting = false;
  private heartbeatInterval: NodeJS.Timeout | null = null;
  private messageHandlers = new Map<string, Array<(payload: any) => void>>();

  constructor(url: string) {
    this.url = url;
    this.setupDefaultHandlers();
  }

  private setupDefaultHandlers() {
    // Handle different message types
    this.on('notification', (payload: NotificationPayload) => {
      // Store notifications in localStorage for persistence
      const notifications = JSON.parse(localStorage.getItem('notifications') || '[]');
      notifications.push({
        ...payload,
        id: Date.now().toString(),
        timestamp: new Date().toISOString()
      });
      localStorage.setItem('notifications', JSON.stringify(notifications.slice(-100))); // Keep last 100

      if (payload.type === 'error' || payload.severity === 'high') {
        toast.error(payload.message);
      } else if (payload.type === 'success') {
        toast.success(payload.message);
      } else {
        toast(payload.message);
      }
    });

    this.on('alert', (payload: AlertPayload) => {
      // Store alerts in localStorage
      const alerts = JSON.parse(localStorage.getItem('alerts') || '[]');
      alerts.push({
        ...payload,
        timestamp: new Date().toISOString()
      });
      localStorage.setItem('alerts', JSON.stringify(alerts.slice(-50))); // Keep last 50
      
      toast.error(`New Alert: ${payload.title}`);
      
      // Dispatch custom event for components to listen to
      window.dispatchEvent(new CustomEvent('newAlert', { detail: payload }));
    });

    this.on('dashboard_update', (payload: DashboardStatsPayload) => {
      // Store dashboard stats
      localStorage.setItem('dashboardStats', JSON.stringify(payload));
      
      // Dispatch custom event
      window.dispatchEvent(new CustomEvent('dashboardUpdate', { detail: payload }));
    });

    this.on('scan_complete', (payload: ScanPayload) => {
      toast.success(`Scan completed for ${payload.integration_name}`);
      
      // Dispatch custom event
      window.dispatchEvent(new CustomEvent('scanComplete', { detail: payload }));
    });

    this.on('scan_failed', (payload: ScanPayload) => {
      toast.error(`Scan failed for ${payload.integration_name}: ${payload.error}`);
      
      // Dispatch custom event
      window.dispatchEvent(new CustomEvent('scanFailed', { detail: payload }));
    });
  }

  connect(token?: string): Promise<void> {
    return new Promise((resolve, reject) => {
      if (this.isConnecting || (this.ws && this.ws.readyState === WebSocket.CONNECTING)) {
        return resolve();
      }

      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        resolve();
        return;
      }

      this.isConnecting = true;
      const wsUrl = token ? `${this.url}?token=${encodeURIComponent(token)}` : this.url;
      
      try {
        this.ws = new WebSocket(wsUrl);
        
        this.ws.onopen = () => {
          console.log('WebSocket connected');
          this.isConnecting = false;
          this.reconnectAttempts = 0;
          this.startHeartbeat();
          resolve();
        };

        this.ws.onmessage = (event) => {
          try {
            const message: WebSocketMessage = JSON.parse(event.data);
            this.handleMessage(message);
          } catch (error) {
            console.error('Failed to parse WebSocket message:', error);
          }
        };

        this.ws.onclose = (event) => {
          console.log('WebSocket disconnected:', event.code, event.reason);
          this.isConnecting = false;
          this.stopHeartbeat();
          
          // Attempt to reconnect unless it was a manual close
          if (event.code !== 1000 && this.reconnectAttempts < this.maxReconnectAttempts) {
            this.scheduleReconnect();
          }
        };

        this.ws.onerror = (error) => {
          console.error('WebSocket error:', error);
          this.isConnecting = false;
          reject(new Error('WebSocket connection failed'));
        };

      } catch (error) {
        this.isConnecting = false;
        reject(error instanceof Error ? error : new Error('Failed to create WebSocket'));
      }
    });
  }

  private handleMessage(message: WebSocketMessage) {
    const handlers = this.messageHandlers.get(message.type);
    if (handlers) {
      handlers.forEach(handler => {
        try {
          handler(message.payload);
        } catch (error) {
          console.error(`Error handling WebSocket message of type ${message.type}:`, error);
        }
      });
    }
  }

  private scheduleReconnect() {
    const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);
    this.reconnectAttempts++;
    
    console.log(`Attempting to reconnect WebSocket in ${delay}ms (attempt ${this.reconnectAttempts})`);
    
    setTimeout(() => {
      if (this.ws?.readyState !== WebSocket.OPEN) {
        this.connect();
      }
    }, delay);
  }

  private startHeartbeat() {
    this.heartbeatInterval = setInterval(() => {
      if (this.ws?.readyState === WebSocket.OPEN) {
        this.send('ping', {});
      }
    }, 30000); // Send ping every 30 seconds
  }

  private stopHeartbeat() {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
  }

  send(type: string, payload: any): boolean {
    if (this.ws?.readyState === WebSocket.OPEN) {
      try {
        const message: WebSocketMessage = {
          type,
          payload,
          timestamp: new Date().toISOString(),
        };
        this.ws.send(JSON.stringify(message));
        return true;
      } catch (error) {
        console.error('Failed to send WebSocket message:', error);
        return false;
      }
    }
    return false;
  }

  on(messageType: string, handler: (payload: any) => void): () => void {
    if (!this.messageHandlers.has(messageType)) {
      this.messageHandlers.set(messageType, []);
    }
    
    const handlers = this.messageHandlers.get(messageType)!;
    handlers.push(handler);

    // Return unsubscribe function
    return () => {
      const index = handlers.indexOf(handler);
      if (index > -1) {
        handlers.splice(index, 1);
      }
    };
  }

  off(messageType: string, handler?: (payload: any) => void) {
    if (handler) {
      const handlers = this.messageHandlers.get(messageType);
      if (handlers) {
        const index = handlers.indexOf(handler);
        if (index > -1) {
          handlers.splice(index, 1);
        }
      }
    } else {
      this.messageHandlers.delete(messageType);
    }
  }

  disconnect() {
    this.stopHeartbeat();
    
    if (this.ws) {
      this.ws.close(1000, 'Manual disconnect');
      this.ws = null;
    }
    
    this.reconnectAttempts = this.maxReconnectAttempts; // Prevent reconnection
  }

  get isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  get connectionState(): string {
    if (!this.ws) return 'disconnected';
    
    switch (this.ws.readyState) {
      case WebSocket.CONNECTING:
        return 'connecting';
      case WebSocket.OPEN:
        return 'connected';
      case WebSocket.CLOSING:
        return 'closing';
      case WebSocket.CLOSED:
        return 'disconnected';
      default:
        return 'unknown';
    }
  }
}

// Global WebSocket manager instance
let wsManager: WebSocketManager | null = null;

export function getWebSocketManager(): WebSocketManager {
  if (!wsManager) {
    // Handle both Vite and regular environments
    const wsUrl = (
      typeof import.meta !== 'undefined' && import.meta.env?.VITE_WS_URL
    ) || 
    (typeof process !== 'undefined' && process.env?.VITE_WS_URL) ||
    'ws://localhost:8000/ws';
    
    wsManager = new WebSocketManager(wsUrl);
  }
  return wsManager;
}

export function useWebSocket() {
  const manager = getWebSocketManager();
  
  React.useEffect(() => {
    const token = localStorage.getItem('token');
    if (token) {
      manager.connect(token).catch(console.error);
    }

    return () => {
      // Don't disconnect on component unmount, keep connection alive
    };
  }, [manager]);

  return {
    isConnected: manager.isConnected,
    connectionState: manager.connectionState,
    send: manager.send.bind(manager),
    on: manager.on.bind(manager),
    off: manager.off.bind(manager),
  };
}

// Utility functions for working with stored data
export function getStoredNotifications(): any[] {
  try {
    return JSON.parse(localStorage.getItem('notifications') || '[]');
  } catch {
    return [];
  }
}

export function getStoredAlerts(): any[] {
  try {
    return JSON.parse(localStorage.getItem('alerts') || '[]');
  } catch {
    return [];
  }
}

export function getDashboardStats(): DashboardStatsPayload | null {
  try {
    const stats = localStorage.getItem('dashboardStats');
    return stats ? JSON.parse(stats) : null;
  } catch {
    return null;
  }
}

export function clearStoredData() {
  localStorage.removeItem('notifications');
  localStorage.removeItem('alerts');
  localStorage.removeItem('dashboardStats');
}

// Event listener helpers for components
export function addWebSocketEventListener(
  eventType: 'newAlert' | 'dashboardUpdate' | 'scanComplete' | 'scanFailed',
  handler: (event: CustomEvent) => void
) {
  window.addEventListener(eventType, handler as EventListener);
  
  return () => {
    window.removeEventListener(eventType, handler as EventListener);
  };
}

export default WebSocketManager;