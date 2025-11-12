// WebSocket Manager for real-time updates and notifications
import { toast } from 'react-hot-toast';
import { store } from '@/store';
import { addNotification } from '@/store/slices/notificationSlice';
import { updateDashboardStats } from '@/store/slices/dashboardSlice';
import { addAlert } from '@/store/slices/alertSlice';
import React from 'react';

/**
 * @typedef {Object} WebSocketMessage
 * @property {string} type
 * @property {any} payload
 * @property {string} [timestamp]
 */

export class WebSocketManager {
  ws = null;
  url;
  reconnectAttempts = 0;
  maxReconnectAttempts = 5;
  reconnectInterval = 1000;
  isConnecting = false;
  heartbeatInterval = null;
  messageHandlers = new Map();

  constructor(url) {
    this.url = url;
    this.setupDefaultHandlers();
  }

  setupDefaultHandlers() {
    // Handle different message types
    this.on('notification', (payload) => {
      store.dispatch(addNotification(payload));
      if (payload.type === 'error' || payload.severity === 'high') {
        toast.error(payload.message);
      } else if (payload.type === 'success') {
        toast.success(payload.message);
      } else {
        toast(payload.message);
      }
    });

    this.on('alert', (payload) => {
      store.dispatch(addAlert(payload));
      toast.error(`New Alert: ${payload.title}`);
    });

    this.on('dashboard_update', (payload) => {
      store.dispatch(updateDashboardStats(payload));
    });

    this.on('scan_complete', (payload) => {
      toast.success(`Scan completed for ${payload.integration_name}`);
    });

    this.on('scan_failed', (payload) => {
      toast.error(`Scan failed for ${payload.integration_name}: ${payload.error}`);
    });
  }

  connect(token) {
    return new Promise((resolve, reject) => {
      if (this.isConnecting || (this.ws && this.ws.readyState === WebSocket.CONNECTING)) {
        return;
      }

      if (this.ws && this.ws.readyState === WebSocket.OPEN) {
        resolve();
        return;
      }

      this.isConnecting = true;
      const wsUrl = token ? `${this.url}?token=${token}` : this.url;
      
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
            const message = JSON.parse(event.data);
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
          reject(error);
        };

      } catch (error) {
        this.isConnecting = false;
        reject(error);
      }
    });
  }

  handleMessage(message) {
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

  scheduleReconnect() {
    const delay = Math.min(1000 * Math.pow(2, this.reconnectAttempts), 30000);
    this.reconnectAttempts++;
    
    console.log(`Attempting to reconnect WebSocket in ${delay}ms (attempt ${this.reconnectAttempts})`);
    
    setTimeout(() => {
      if (this.ws?.readyState !== WebSocket.OPEN) {
        this.connect();
      }
    }, delay);
  }

  startHeartbeat() {
    this.heartbeatInterval = setInterval(() => {
      if (this.ws?.readyState === WebSocket.OPEN) {
        this.send('ping', {});
      }
    }, 30000); // Send ping every 30 seconds
  }

  stopHeartbeat() {
    if (this.heartbeatInterval) {
      clearInterval(this.heartbeatInterval);
      this.heartbeatInterval = null;
    }
  }

  send(type, payload) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      try {
        const message = {
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

  on(messageType, handler) {
    if (!this.messageHandlers.has(messageType)) {
      this.messageHandlers.set(messageType, []);
    }
    
    const handlers = this.messageHandlers.get(messageType);
    handlers.push(handler);

    // Return unsubscribe function
    return () => {
      this.off(messageType, handler);
    };
  }

  off(messageType, handler) {
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
    this.reconnectAttempts = this.maxReconnectAttempts; // Prevent reconnection
    
    if (this.ws) {
      this.ws.close(1000, 'Manual disconnect');
      this.ws = null;
    }
  }

  get isConnected() {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  get connectionState() {
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
let wsManager = null;

export function getWebSocketManager() {
  if (!wsManager) {
    const wsUrl = import.meta.env.VITE_WS_URL || 'ws://localhost:8000/ws';
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