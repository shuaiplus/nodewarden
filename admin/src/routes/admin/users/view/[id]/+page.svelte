<script lang="ts">
  import UserDetailView from '$lib/UserDetailView.svelte';

  let { data } = $props();
</script>

<UserDetailView detail={data.detail} csrf={data.csrf ?? ''} />
