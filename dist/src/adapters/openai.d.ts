import type { LLMMessage } from "../guard/types.js";
type OpenAIChatClientLike = {
    chat: {
        completions: {
            create: (args: any) => Promise<any>;
        };
    };
};
export declare function openaiChatCaller(client: OpenAIChatClientLike, model?: string): (messages: LLMMessage[]) => Promise<string>;
export {};
