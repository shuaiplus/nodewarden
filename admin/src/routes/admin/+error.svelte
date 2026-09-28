<script lang="ts">
  import { resolve } from '$app/paths';
  import { page } from '$app/state';
  import Heading from '$lib/Heading.svelte';

  const TITLES: Record<number, string> = {
    400: 'Bad request',
    403: 'Forbidden',
    404: 'Not found',
    405: 'Method not allowed',
    429: 'Too many requests',
  };
</script>

<Heading title={TITLES[page.status] ?? 'Server error'} />
<p>{page.error?.message}</p>
{#if page.status === 400}<p><a href={resolve('/admin/login')}>Request a new sign-in link</a></p>{/if}
