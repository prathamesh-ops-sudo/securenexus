import { encodingForModel } from "js-tiktoken";

const encoder = encodingForModel("gpt-4o");

export function countTokens(text: string): number {
  return encoder.encode(text).length;
}
