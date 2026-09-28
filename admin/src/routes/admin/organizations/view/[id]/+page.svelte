<script lang="ts">
  import OrganizationDetailView from '$lib/OrganizationDetailView.svelte';

  let { data } = $props();
</script>

<OrganizationDetailView detail={data.detail} csrf={data.csrf ?? ''} />
