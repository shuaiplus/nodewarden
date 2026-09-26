import { html, toSafeUrl, type SafeUrl } from '../utils/html';
import { buildRegisterVerifyUrl, buildOrganizationInviteUrl, sanitizeForEmail, type OrganizationInvite } from './mail';
import { ORG_INVITE_TTL_DAYS } from '../utils/jwt';

export type MailContent = { subject: string; paragraphs: string[]; action?: { label: string; url: SafeUrl } };
export const MAIL_TEMPLATES = {
  newDeviceLogin: {
    throttle: 'exempt',
    render: (model: { device: string; time: string; ip: string }): MailContent => ({
      subject: 'New device signed in to NodeWarden',
      paragraphs: [`A new ${sanitizeForEmail(model.device)} device signed in to your account.`, `Time (UTC): ${sanitizeForEmail(model.time)}. IP address: ${sanitizeForEmail(model.ip)}.`, 'If this was not you, change your master password and revoke your sessions.'],
    }),
  },
  adminSignIn: {
    throttle: 'exempt',
    render: (model: { url: SafeUrl }): MailContent => ({
      subject: 'Sign in to NodeWarden administration',
      paragraphs: ['Use this link in the browser where you requested it to sign in to administration.', 'This single-use link expires in 15 minutes. Ignore this email if you did not request it.'],
      action: { label: 'Sign in', url: model.url },
    }),
  },
  registerVerification: {
    throttle: 'user',
    render: (model: { vaultOrigin: string; email: string; token: string }): MailContent => ({
      subject: 'Verify your NodeWarden email',
      paragraphs: ['Verify your email to finish creating your NodeWarden account.', 'This link expires in 30 minutes. If you did not request an account, ignore this email.'],
      action: { label: 'Verify email', url: toSafeUrl(new URL(buildRegisterVerifyUrl(model.vaultOrigin, model.email, model.token))) },
    }),
  },
  organizationInvite: {
    throttle: 'user',
    render: (model: OrganizationInvite): MailContent => ({
      subject: `Join ${sanitizeForEmail(model.organizationName)}`,
      paragraphs: [`You have been invited to join the ${sanitizeForEmail(model.organizationName)} organization.`, `This link expires in ${ORG_INVITE_TTL_DAYS} days.`],
      action: { label: 'Accept invitation', url: toSafeUrl(new URL(buildOrganizationInviteUrl(model))) },
    }),
  },
} satisfies Record<string, { throttle: 'user' | 'exempt'; render: (model: never) => MailContent }>;
export type TemplateName = keyof typeof MAIL_TEMPLATES;
export type TemplateModel<N extends TemplateName> = Parameters<(typeof MAIL_TEMPLATES)[N]['render']>[0];

export function renderMail(content: MailContent): { subject: string; text: string; html: string } {
  const subject = content.subject.replace(/[\p{Cc}\p{Cf}\u2028\u2029]/gu, ' ').replace(/\s+/g, ' ').trim().slice(0, 100);
  const footer = 'NodeWarden account notification.';
  return {
    subject,
    text: [...content.paragraphs, ...(content.action ? [content.action.url] : []), footer].join('\n\n'),
    html: html`<!doctype html><html><body>${content.paragraphs.map((paragraph) => html`<p>${paragraph}</p>`)}${content.action ? html`<p><a href="${content.action.url}">${content.action.label}</a></p>` : html``}<hr><p>${footer}</p></body></html>`.safeHtml,
  };
}
