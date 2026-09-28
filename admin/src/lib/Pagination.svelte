<script lang="ts">
  import { resolve } from '$app/paths';
  import { page } from '$app/state';

  let { path, current, hasMore }: { path: '/admin/users' | '/admin/organizations'; current: number; hasMore: boolean } =
    $props();
  // Page links keep the list's filters and change only the page number.
  const pageQuery = (value: number) => {
    const params = new URLSearchParams(page.url.searchParams);
    params.set('page', String(value));
    return params.toString();
  };
</script>

<nav>
  {#if current > 1}<a href={resolve(`${path}?${pageQuery(current - 1)}`)}>Previous</a>{/if}
  <span>Page {current}</span>
  {#if hasMore}<a href={resolve(`${path}?${pageQuery(current + 1)}`)}>Next</a>{/if}
</nav>
