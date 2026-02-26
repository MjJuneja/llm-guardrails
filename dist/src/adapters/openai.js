"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.openaiChatCaller = openaiChatCaller;
function openaiChatCaller(client, model = "gpt-4o-mini") {
    const caller = async (messages) => {
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
