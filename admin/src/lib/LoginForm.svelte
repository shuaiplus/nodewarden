<script lang="ts">
  import Heading from './Heading.svelte';

  let { returnPath, mailEnabled, message }: { returnPath: string; mailEnabled: boolean; message: string } = $props();
</script>

<Heading title="Administrator sign-in" />
{#if !mailEnabled}
  <p class="notice">Sign-in links cannot be sent. Check the instance email configuration.</p>
{/if}
{#if message}<p class="notice">{message}</p>{/if}
<form method="post" action="/admin/login">
  <label>Email <input type="email" name="email" required maxlength="256" autocomplete="email" /></label>
  <input type="hidden" name="returnUrl" value={returnPath} />
  <button type="submit">Send sign-in link</button>
</form>
