<script lang="ts">
  let { action, csrf, button }: { action: string; csrf: string; button: string } = $props();
</script>

<form method="post" {action}>
  <input type="hidden" name="csrf" value={csrf} />
  <button type="submit">{button}</button>
</form>
