<script lang="ts">
  let { fields }: { fields: Array<[string, string | number]> } = $props();
</script>

<dl>
  {#each fields as [name, value] (name)}<dt>{name}</dt>
    <dd>{value}</dd>{/each}
</dl>
