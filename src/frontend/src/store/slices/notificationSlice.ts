import { createSlice, PayloadAction } from '@reduxjs/toolkit';
import { NotificationState } from '@/types';

interface NotificationsState {
  notifications: NotificationState[];
}

const initialState: NotificationsState = {
  notifications: [],
};

const notificationSlice = createSlice({
  name: 'notifications',
  initialState,
  reducers: {
    addNotification: (state, action: PayloadAction<Omit<NotificationState, 'id'>>) => {
      const notification: NotificationState = {
        ...action.payload,
        id: `notification_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      };
      state.notifications.push(notification);
    },
    
    removeNotification: (state, action: PayloadAction<string>) => {
      state.notifications = state.notifications.filter(
        (notification) => notification.id !== action.payload
      );
    },
    
    clearAllNotifications: (state) => {
      state.notifications = [];
    },
    
    // Convenience actions for different notification types
    addSuccessNotification: (state, action: PayloadAction<{ title: string; message: string }>) => {
      const notification: NotificationState = {
        id: `notification_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        type: 'success',
        ...action.payload,
        duration: 5000,
      };
      state.notifications.push(notification);
    },
    
    addErrorNotification: (state, action: PayloadAction<{ title: string; message: string }>) => {
      const notification: NotificationState = {
        id: `notification_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        type: 'error',
        ...action.payload,
        duration: 0, // Error notifications don't auto-dismiss
      };
      state.notifications.push(notification);
    },
    
    addWarningNotification: (state, action: PayloadAction<{ title: string; message: string }>) => {
      const notification: NotificationState = {
        id: `notification_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        type: 'warning',
        ...action.payload,
        duration: 8000,
      };
      state.notifications.push(notification);
    },
    
    addInfoNotification: (state, action: PayloadAction<{ title: string; message: string }>) => {
      const notification: NotificationState = {
        id: `notification_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        type: 'info',
        ...action.payload,
        duration: 6000,
      };
      state.notifications.push(notification);
    },
  },
});

export const {
  addNotification,
  removeNotification,
  clearAllNotifications,
  addSuccessNotification,
  addErrorNotification,
  addWarningNotification,
  addInfoNotification,
} = notificationSlice.actions;

export default notificationSlice.reducer;