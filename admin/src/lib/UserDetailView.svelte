<script lang="ts">
  import type { UserDetail } from '../../../src/admin/portal-contract';
  import ConfirmForm from './ConfirmForm.svelte';
  import CsrfForm from './CsrfForm.svelte';
  import Fields from './Fields.svelte';
  import Heading from './Heading.svelte';
  import { userActionPath } from './paths';

  let { detail, csrf, notice }: { detail: UserDetail; csrf: string; notice?: string } = $props();
</script>

<Heading title="User details" />
{#if notice}<p class="notice">{notice}</p>{/if}
<Fields fields={detail.fields} />
{#if !detail.emailVerified}
  <ConfirmForm
    action={userActionPath(detail.id, 'verify-email')}
    {csrf}
    prompt="Type {detail.email} to confirm email verification"
    button={detail.verificationGrantsVaultAdmin ? 'Verify email and grant vault admin' : 'Verify email'}
  />
{/if}
<CsrfForm
  action={userActionPath(detail.id, detail.status === 'active' ? 'disable' : 'enable')}
  {csrf}
  button={detail.status === 'active' ? 'Disable user' : 'Enable user'}
/>
{#if detail.hasTwoFactor}
  <ConfirmForm
    action={userActionPath(detail.id, 'remove-2fa')}
    {csrf}
    prompt="Type {detail.email} to remove two-step login"
    button="Remove two-step login"
  />
{/if}
<ConfirmForm
  action="/admin/users/delete/{encodeURIComponent(detail.id)}"
  {csrf}
  prompt="Type {detail.email} to confirm deletion"
  button="Delete"
/>
