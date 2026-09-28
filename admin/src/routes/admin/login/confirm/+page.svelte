<script lang="ts">
  import Heading from '$lib/Heading.svelte';
  import LoginForm from '$lib/LoginForm.svelte';
  import { LOGIN_MESSAGES } from '$lib/messages';

  let { data, form } = $props();
</script>

{#if form?.invalid}
  <LoginForm returnPath="/admin" mailEnabled={data.mailEnabled} message={LOGIN_MESSAGES.invalid} />
{:else}
  <Heading title="Confirm administrator sign-in" />
  <form method="post" action="/admin/login/confirm">
    <input type="hidden" name="token" value={data.token} />
    <button type="submit">Sign in</button>
  </form>
{/if}
