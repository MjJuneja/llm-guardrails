import type { LLMCaller, LLMMessage } from "../guard/types.js";

type OpenAIChatClientLike = {
  chat: {
    completions: {
      create: (args: any) => Promise<any>;
    };
  };
};

export function openaiChatCaller(client: OpenAIChatClientLike, model = "gpt-4o-mini"): (messages: LLMMessage[]) => Promise<string> {
  const caller: LLMCaller = async (messages) => {
    const res = await client.chat.completions.create({
      model,
      messages: messages.map((m) => ({ role: m.role, content: m.content }))
    });

    // common OpenAI response shape
    const text = res?.choices?.[0]?.message?.content ?? "";
    return String(text);
  };
  return caller;
}