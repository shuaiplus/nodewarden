<script lang="ts">
  import UserDetailView from '$lib/UserDetailView.svelte';

  let { data, form } = $props();
</script>

<UserDetailView detail={data.detail} csrf={data.csrf ?? ''} notice={form?.notice} />
