<script lang="ts">
  import OrganizationDetailView from '$lib/OrganizationDetailView.svelte';

  let { data, form } = $props();
</script>

<OrganizationDetailView detail={data.detail} csrf={data.csrf ?? ''} notice={form?.notice} />
