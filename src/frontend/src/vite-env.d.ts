/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_API_URL: string
  readonly VITE_WS_URL: string
  readonly VITE_APP_TITLE: string
  readonly VITE_APP_DESCRIPTION: string
  readonly VITE_SENTRY_DSN?: string
  readonly VITE_GA_TRACKING_ID?: string
  readonly VITE_ENVIRONMENT: 'development' | 'staging' | 'production'
}

interface ImportMeta {
  readonly env: ImportMetaEnv
}

declare const __APP_VERSION__: string