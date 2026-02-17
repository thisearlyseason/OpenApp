const STRAICO_API_KEY = process.env.STRAICO_API_KEY!
const STRAICO_API_BASE_URL = process.env.STRAICO_API_BASE_URL || 'https://api.straico.com/v1'

export interface StraicoResponse {
  success: boolean
  data?: {
    completion?: {
      choices?: Array<{
        message?: {
          content: string
        }
      }>
    }
    words?: number
  }
  error?: string
}

export async function sendPromptToStraico(
  prompt: string,
  maxTokens: number = 2000
): Promise<{ response: string; tokensUsed: number }> {
  const response = await fetch(`${STRAICO_API_BASE_URL}/prompt/completion`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${STRAICO_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      model: 'openai/gpt-4o-mini',
      message: prompt,
      max_tokens: maxTokens
    })
  })

  if (!response.ok) {
    throw new Error(`Straico API error: ${response.status}`)
  }

  const data: StraicoResponse = await response.json()
  
  let responseText = ''
  if (data.data?.completion?.choices?.[0]?.message?.content) {
    responseText = data.data.completion.choices[0].message.content
  } else if (data.data?.completion) {
    responseText = String(data.data.completion)
  }

  return {
    response: responseText,
    tokensUsed: data.data?.words || 0
  }
}
