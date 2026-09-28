<script lang="ts">
  import { resolve } from '$app/paths';
  import Heading from '$lib/Heading.svelte';
  import Pagination from '$lib/Pagination.svelte';

  let { data } = $props();
</script>

<Heading title="Users" />
<form method="get" action="/admin/users">
  <label>Email prefix <input name="email" value={data.email} /></label>
  <input type="hidden" name="count" value={data.results.count} />
  <button type="submit">Search</button>
</form>
<table>
  <thead>
    <tr><th>Email</th><th>Name</th><th>Created</th><th>Status</th><th>Vault role</th><th>Two-factor</th></tr>
  </thead>
  <tbody>
    {#each data.results.rows as user (user.id)}
      <tr>
        <td><a href={resolve('/admin/users/view/[id]', { id: user.id })}>{user.email}</a></td>
        <td>{user.name ?? ''}</td>
        <td>{user.createdAt}</td>
        <td>{user.status}</td>
        <td>{user.role}</td>
        <td>{user.twoFactor ? 'Yes' : 'No'}</td>
      </tr>
    {/each}
  </tbody>
</table>
<Pagination path="/admin/users" current={data.results.page} hasMore={data.results.hasMore} />
