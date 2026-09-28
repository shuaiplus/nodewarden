<script lang="ts">
  let { action, csrf, prompt, button }: { action: string; csrf: string; prompt: string; button: string } = $props();
</script>

<form method="post" {action}>
  <input type="hidden" name="csrf" value={csrf} />
  <label>{prompt} <input name="confirmation" required autocomplete="off" /></label>
  <button type="submit">{button}</button>
</form>
