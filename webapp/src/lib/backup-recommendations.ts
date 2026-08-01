export interface RecommendedStorageLink {
  name: string;
  capacity: string;
}

export interface RecommendedProviderBase {
  id: 'infinicloud' | 'koofr' | 'pcloud' | 'backblaze-b2' | 'cloudflare-r2' | 'tigris';
  name: string;
  capacity: string;
  protocol: 'webdav' | 's3';
  signupUrl: string;
  hasAffiliateLink?: boolean;
}

export interface InfinicloudProvider extends RecommendedProviderBase {
  id: 'infinicloud';
  referralCode: string;
}

export interface KoofrProvider extends RecommendedProviderBase {
  id: 'koofr';
  passwordUrl: string;
  storageUrl: string;
  linkedStorages: RecommendedStorageLink[];
}

export interface PcloudProvider extends RecommendedProviderBase {
  id: 'pcloud';
}

export interface BackblazeB2Provider extends RecommendedProviderBase {
  id: 'backblaze-b2';
  bucketsUrl: string;
  applicationKeysUrl: string;
}

export interface CloudflareR2Provider extends RecommendedProviderBase {
  id: 'cloudflare-r2';
  bucketUrl: string;
  apiTokenUrl: string;
}

export interface TigrisProvider extends RecommendedProviderBase {
  id: 'tigris';
  bucketUrl: string;
  accessKeyUrl: string;
}

export type RecommendedProvider = InfinicloudProvider | KoofrProvider | PcloudProvider | BackblazeB2Provider | CloudflareR2Provider | TigrisProvider;

export const RECOMMENDED_PROVIDERS: RecommendedProvider[] = [
  {
    id: 'infinicloud',
    name: 'InfiniCLOUD',
    capacity: '25G',
    protocol: 'webdav',
    signupUrl: 'https://infini-cloud.net/en/',
    referralCode: '2HC5E',
  },
  {
    id: 'koofr',
    name: 'Koofr',
    capacity: '10G',
    protocol: 'webdav',
    signupUrl: 'https://app.koofr.net/signup',
    passwordUrl: 'https://app.koofr.net/app/admin/preferences/password',
    storageUrl: 'https://app.koofr.net/app/storage/',
    linkedStorages: [
      { name: 'Google Drive', capacity: '15G' },
      { name: 'OneDrive', capacity: '5G' },
      { name: 'Dropbox', capacity: '2G' },
    ],
  },
  {
    id: 'pcloud',
    name: 'pCloud',
    capacity: '10G',
    protocol: 'webdav',
    signupUrl: 'https://u.pcloud.com/#/register?invite=GITx7ZvEU1N7',
    hasAffiliateLink: true,
  },
  {
    id: 'backblaze-b2',
    name: 'Backblaze B2',
    capacity: '10G',
    protocol: 's3',
    signupUrl: 'https://secure.backblaze.com/user_signin.htm',
    bucketsUrl: 'https://secure.backblaze.com/b2_buckets.htm',
    applicationKeysUrl: 'https://secure.backblaze.com/app_keys.htm',
  },
  {
    id: 'cloudflare-r2',
    name: 'Cloudflare R2',
    capacity: '10G',
    protocol: 's3',
    signupUrl: 'https://dash.cloudflare.com/?to=/:account/r2/new',
    bucketUrl: 'https://dash.cloudflare.com/?to=/:account/r2/new',
    apiTokenUrl: 'https://dash.cloudflare.com/?to=/:account/r2/api-tokens/create?type=user',
  },
  {
    id: 'tigris',
    name: 'Tigris',
    capacity: '5G',
    protocol: 's3',
    signupUrl: 'https://console.storage.dev/signup',
    bucketUrl: 'https://console.storage.dev/createbucket',
    accessKeyUrl: 'https://console.storage.dev/createaccesskey',
  },
];

export function hasLinkedStorages(provider: RecommendedProvider): provider is KoofrProvider {
  return provider.id === 'koofr';
}
