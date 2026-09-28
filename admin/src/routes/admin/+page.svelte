<script lang="ts">
  import Fields from '$lib/Fields.svelte';
  import Heading from '$lib/Heading.svelte';

  let { data } = $props();
</script>

<Heading title="Administration" />
<p>Signed in as {data.adminEmail}</p>
<Fields fields={data.dashboard.settings} />
<h2>Recent administrator events</h2>
<table>
  <thead><tr><th>Time</th><th>Action</th><th>Administrator</th></tr></thead>
  <tbody>
    {#each data.dashboard.events as event, index (index)}
      <tr><td>{event.createdAt}</td><td>{event.action}</td><td>{event.adminEmail}</td></tr>
    {/each}
  </tbody>
</table>
