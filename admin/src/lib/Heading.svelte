<script lang="ts">
  let { title }: { title: string } = $props();
</script>

<svelte:head><title>{title} · NodeWarden</title></svelte:head>
<h1>{title}</h1>
