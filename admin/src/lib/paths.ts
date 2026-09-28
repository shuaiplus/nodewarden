export const userViewPath = (id: string) => `/admin/users/view/${encodeURIComponent(id)}`;
export const userActionPath = (id: string, action: string) => `/admin/users/${encodeURIComponent(id)}/${action}`;
export const organizationViewPath = (id: string) => `/admin/organizations/view/${encodeURIComponent(id)}`;
