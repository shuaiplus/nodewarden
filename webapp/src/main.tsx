import { render } from 'preact';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import App from './App';
import { initI18n } from './lib/i18n';
import { registerNodeWardenServiceWorker } from './lib/pwa';
import { loadSdk } from './lib/sdk';
import './tailwind.css';
import './styles.css';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 30_000,
    },
  },
});

const root = document.getElementById('root')!;
root.setAttribute('translate', 'no');

function renderApp(): void {
  render(
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>,
    root
  );
}

// Vault crypto runs on the Bitwarden SDK, so its WASM (fetched alongside the locale) must be linked
// before the app can unlock. Render either way; a failed load still surfaces as a rejection.
const sdkLoaded = loadSdk();
void initI18n().finally(() => sdkLoaded).finally(() => {
  renderApp();
  registerNodeWardenServiceWorker();
});
