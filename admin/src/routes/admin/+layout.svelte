<script lang="ts">
  import { resolve } from '$app/paths';
  import CsrfForm from '$lib/CsrfForm.svelte';

  let { data, children } = $props();
</script>

<main>
  {#if data.csrf}
    <nav>
      <a href={resolve('/admin')}>Dashboard</a>
      <a href={resolve('/admin/users')}>Users</a>
      <a href={resolve('/admin/organizations')}>Organizations</a>
      <CsrfForm action="/admin/login/logout" csrf={data.csrf} button="Sign out" />
    </nav>
  {/if}
  {@render children()}
</main>
