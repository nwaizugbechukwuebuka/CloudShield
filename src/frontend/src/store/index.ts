import { configureStore } from '@reduxjs/toolkit';
import { TypedUseSelectorHook, useDispatch, useSelector } from 'react-redux';
import authReducer from './slices/authSlice';
import uiReducer from './slices/uiSlice';
import notificationReducer from './slices/notificationSlice';
import integrationReducer from './slices/integrationSlice';
import findingReducer from './slices/findingSlice';
import alertReducer from './slices/alertSlice';
import dashboardReducer from './slices/dashboardSlice';

export const store = configureStore({
  reducer: {
    auth: authReducer,
    ui: uiReducer,
    notifications: notificationReducer,
    integrations: integrationReducer,
    findings: findingReducer,
    alerts: alertReducer,
    dashboard: dashboardReducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: {
        // Ignore these action types
        ignoredActions: [
          'auth/login/fulfilled',
          'auth/refreshToken/fulfilled',
          'persist/PERSIST',
          'persist/REHYDRATE',
        ],
        // Ignore these field paths in all actions
        ignoredActionsPaths: ['meta.arg', 'payload.timestamp'],
        // Ignore these paths in the state
        ignoredPaths: ['auth.tokens.timestamp'],
      },
    }),
  devTools: import.meta.env.VITE_ENVIRONMENT !== 'production',
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;

// Use throughout your app instead of plain `useDispatch` and `useSelector`
export const useAppDispatch = () => useDispatch<AppDispatch>();
export const useAppSelector: TypedUseSelectorHook<RootState> = useSelector;