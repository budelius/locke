/**
 * Config flattening — nested JSON to SCREAMING_SNAKE_CASE key-value pairs.
 */

import { CollisionError } from "./errors.js";

export function flattenConfig(
  config: Record<string, unknown>,
): Record<string, string> {
  const result: Record<string, string> = {};
  const sources: Record<string, string> = {};

  flattenRecursive(config, "", "", result, sources);

  // Sort alphabetically
  const sorted: Record<string, string> = {};
  for (const key of Object.keys(result).sort()) {
    sorted[key] = result[key];
  }
  return sorted;
}

function flattenRecursive(
  obj: Record<string, unknown>,
  prefix: string,
  path: string,
  result: Record<string, string>,
  sources: Record<string, string>,
): void {
  for (const [key, value] of Object.entries(obj)) {
    const flatKey = prefix ? `${prefix}_${key}`.toUpperCase() : key.toUpperCase();
    const sourcePath = path ? `${path}.${key}` : key;

    if (value !== null && typeof value === "object" && !Array.isArray(value)) {
      flattenRecursive(
        value as Record<string, unknown>,
        flatKey,
        sourcePath,
        result,
        sources,
      );
    } else {
      if (flatKey in result) {
        throw new CollisionError(flatKey, sources[flatKey], sourcePath);
      }
      result[flatKey] = String(value);
      sources[flatKey] = sourcePath;
    }
  }
}
