<script lang="ts">
  import type { OrganizationDetail } from '../../../src/admin/portal-contract';
  import ConfirmForm from './ConfirmForm.svelte';
  import Fields from './Fields.svelte';
  import Heading from './Heading.svelte';

  let { detail, csrf, notice }: { detail: OrganizationDetail; csrf: string; notice?: string } = $props();
</script>

<Heading title="Organization details" />
{#if notice}<p class="notice">{notice}</p>{/if}
<Fields fields={detail.fields} />
<h2>Administrators</h2>
<table>
  <thead><tr><th>Email</th><th>Type</th><th>Status</th></tr></thead>
  <tbody>
    {#each detail.administrators as admin, index (index)}
      <tr><td>{admin.email}</td><td>{admin.type}</td><td>{admin.status}</td></tr>
    {/each}
  </tbody>
</table>
<ConfirmForm
  action="/admin/organizations/delete/{encodeURIComponent(detail.id)}"
  {csrf}
  prompt="Type {detail.name} to confirm deletion"
  button="Delete"
/>
