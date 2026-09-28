<script lang="ts">
  import { resolve } from '$app/paths';
  import Heading from '$lib/Heading.svelte';
  import Pagination from '$lib/Pagination.svelte';

  let { data } = $props();
</script>

<Heading title="Organizations" />
<form method="get" action="/admin/organizations">
  <label>Name contains <input name="name" value={data.name} /></label>
  <label>Member email <input name="userEmail" value={data.userEmail} /></label>
  <input type="hidden" name="count" value={data.results.count} />
  <button type="submit">Search</button>
</form>
<table>
  <thead><tr><th>Name</th><th>Created</th><th>Billing email</th></tr></thead>
  <tbody>
    {#each data.results.rows as org (org.id)}
      <tr>
        <td><a href={resolve('/admin/organizations/view/[id]', { id: org.id })}>{org.name}</a></td>
        <td>{org.createdAt}</td>
        <td>{org.billingEmail}</td>
      </tr>
    {/each}
  </tbody>
</table>
<Pagination path="/admin/organizations" current={data.results.page} hasMore={data.results.hasMore} />
