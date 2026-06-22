/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_QEETID_API_URL: string;
  readonly VITE_QEETID_CLIENT_ID: string;
  readonly VITE_QEETID_REDIRECT_URI: string;
  readonly VITE_QEETID_POST_LOGOUT_URI?: string;
  readonly VITE_QEETID_SCOPES?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
