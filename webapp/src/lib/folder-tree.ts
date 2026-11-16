import type { Folder } from './types';

export interface FolderTreeNode {
  folder: Folder;
  label: string;
  children: FolderTreeNode[];
}

export interface FolderTreeRow extends FolderTreeNode {
  depth: number;
}

// The server stores encrypted full names. Nesting is a client-side convention:
// only an existing, exactly matching parent makes a slash-delimited name nest.
// Keep every folder ID, including duplicate names and paths with missing parents.
export function buildFolderTree(sortedFolders: readonly Folder[]): FolderTreeNode[] {
  const nodes = sortedFolders.map((folder): FolderTreeNode => ({
    folder,
    label: folder.decName || folder.name || folder.id,
    children: [],
  }));
  const byName = new Map<string, FolderTreeNode>();
  for (const node of nodes) {
    if (!byName.has(node.label)) byName.set(node.label, node);
  }

  const roots: FolderTreeNode[] = [];
  for (const node of nodes) {
    const separator = node.label.lastIndexOf('/');
    const parent = separator > 0 ? byName.get(node.label.slice(0, separator)) : undefined;
    if (parent && separator < node.label.length - 1) {
      parent.children.push(node);
      node.label = node.label.slice(separator + 1);
    } else {
      roots.push(node);
    }
  }
  return roots;
}

export function flattenFolderTree(
  roots: readonly FolderTreeNode[],
  collapsedIds: ReadonlySet<string>
): FolderTreeRow[] {
  const rows: FolderTreeRow[] = [];
  const pending = roots.map((node) => ({ ...node, depth: 0 })).reverse();
  // Iterate rather than recurse so imported paths do not impose a depth limit.
  while (pending.length) {
    const row = pending.pop()!;
    rows.push(row);
    if (collapsedIds.has(row.folder.id)) continue;
    for (let i = row.children.length - 1; i >= 0; i--) {
      pending.push({ ...row.children[i], depth: row.depth + 1 });
    }
  }
  return rows;
}
