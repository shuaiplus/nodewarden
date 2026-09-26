import { html, toSafeUrl, type SafeUrl } from '../utils/html';
import { buildRegisterVerifyUrl, buildOrganizationInviteUrl, sanitizeForEmail, type OrganizationInvite } from './mail';
import { ORG_INVITE_TTL_DAYS } from '../utils/jwt';

export type MailContent = { subject: string; paragraphs: string[]; action?: { label: string; url: SafeUrl } };
export const MAIL_TEMPLATES = {
  passwordHint: {
    throttle: 'user',
    render: (model: { hint: string }): MailContent => ({ subject: 'Your NodeWarden password hint', paragraphs: ['You requested your saved master password hint.', sanitizeForEmail(model.hint), 'NodeWarden cannot recover your master password.'] }),
  },
  noPasswordHint: {
    throttle: 'user',
    render: (_model: Record<string, never>): MailContent => ({ subject: 'Your NodeWarden password hint', paragraphs: ['No master password hint is saved for your account.', 'NodeWarden cannot recover your master password.'] }),
  },
  twoFactorRecovered: {
    throttle: 'exempt',
    render: (model: { time: string; ip: string }): MailContent => ({
      subject: 'NodeWarden two-step login was recovered',
      paragraphs: ['A recovery code was used to remove two-step login from your account.', `Time (UTC): ${sanitizeForEmail(model.time)}. IP address: ${sanitizeForEmail(model.ip)}.`, 'If this was not you, change your master password and review your account security.'],
    }),
  },
  failedTwoFactor: {
    throttle: 'exempt',
    render: (model: { provider: number; time: string; ip: string }): MailContent => ({
      subject: 'Unsuccessful two-step sign-in to NodeWarden',
      paragraphs: [`A sign-in with your password failed its two-step check (${({ 0: 'Authenticator', 3: 'YubiKey', 7: 'Passkey', 8: 'Recovery code' } as Record<number, string>)[model.provider] ?? 'Unknown provider'}).`, `Time (UTC): ${sanitizeForEmail(model.time)}. IP address: ${sanitizeForEmail(model.ip)}.`, 'If this was not you, change your master password.'],
    }),
  },
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
  emergencyAccessInvite: {
    throttle: 'user',
    render: (model: { vaultOrigin: string; id: string; grantorName: string; grantorEmail: string; token: string }): MailContent => ({
      subject: 'Emergency access invitation',
      paragraphs: [`${sanitizeForEmail(model.grantorName)} invited you to be an emergency contact for their NodeWarden account.`, `This invitation expires in ${ORG_INVITE_TTL_DAYS} days.`],
      action: { label: 'Accept invitation', url: toSafeUrl(new URL(`${model.vaultOrigin}/#/accept-emergency?${new URLSearchParams({ id: model.id, name: model.grantorName, email: model.grantorEmail, token: model.token })}`)) },
    }),
  },
  emergencyAccessAccepted: {
    throttle: 'user',
    render: (model: { name: string }): MailContent => ({
      subject: 'Emergency contact accepted your invitation',
      paragraphs: [`${sanitizeForEmail(model.name)} accepted your emergency-access invitation. Confirm this contact in your vault to enable access.`],
    }),
  },
  emergencyAccessConfirmed: {
    throttle: 'user',
    render: (model: { name: string }): MailContent => ({
      subject: 'Emergency access confirmed',
      paragraphs: [`${sanitizeForEmail(model.name)} confirmed you as an emergency contact. You can now request emergency access from your vault.`],
    }),
  },
  emergencyAccessRecoveryInitiated: {
    throttle: 'exempt',
    render: (model: { name: string; accessType: string; daysLeft: number }): MailContent => ({
      subject: 'Emergency access requested',
      paragraphs: [`${sanitizeForEmail(model.name)} requested permission to ${sanitizeForEmail(model.accessType)}.`, `Access will be approved after ${model.daysLeft} days. Open your vault to approve or reject the request.`],
    }),
  },
  emergencyAccessApproved: {
    throttle: 'user',
    render: (model: { name: string }): MailContent => ({
      subject: 'Emergency access approved',
      paragraphs: [`Your emergency access to ${sanitizeForEmail(model.name)} has been approved. Open your vault to continue.`],
    }),
  },
  emergencyAccessRejected: {
    throttle: 'user',
    render: (model: { name: string }): MailContent => ({
      subject: 'Emergency access request rejected',
      paragraphs: [`${sanitizeForEmail(model.name)} rejected your emergency-access request. Your emergency contact relationship remains confirmed.`],
    }),
  },
  emergencyAccessTimedOut: {
    throttle: 'exempt',
    render: (model: { name: string }): MailContent => ({
      subject: 'Emergency access waiting period ended',
      paragraphs: [`The waiting period for ${sanitizeForEmail(model.name)} has ended. Their emergency access to your account is now approved.`],
    }),
  },
  emergencyAccessReminder: {
    throttle: 'exempt',
    render: (model: { name: string; daysLeft: number }): MailContent => ({
      subject: 'Emergency access waiting period ends soon',
      paragraphs: [`${sanitizeForEmail(model.name)} will receive emergency access to your account in ${model.daysLeft} day(s). Open your vault to review or reject the request.`],
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
