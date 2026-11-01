import { createHash } from "node:crypto";
export * from "../extension/lib/domain-rules.js";

export function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}
