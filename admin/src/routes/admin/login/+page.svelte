<script lang="ts">
  import LoginForm from '$lib/LoginForm.svelte';

  let { data, form } = $props();
</script>

<LoginForm
  returnPath={form?.returnPath ?? data.returnPath}
  mailEnabled={data.mailEnabled}
  message={form?.message ?? data.message}
/>
