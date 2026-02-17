import { createClient } from '@supabase/supabase-js'
import { NextRequest, NextResponse } from 'next/server'
import { v4 as uuidv4 } from 'uuid'

// Types
interface RouteParams {
  params: { path?: string[] }
}

// Supabase clients
function createServerClient() {
  return createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.SUPABASE_SERVICE_ROLE_KEY!,
    {
      auth: {
        autoRefreshToken: false,
        persistSession: false
      }
    }
  )
}

function createAnonClient() {
  return createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
  )
}

// Constants
const INITIAL_CREDITS = 100000
const CREDITS_PER_REQUEST = parseInt(process.env.CREDITS_PER_REQUEST || '1')
const MAX_TOKENS = parseInt(process.env.MAX_TOKENS || '2000')
const STRAICO_API_KEY = process.env.STRAICO_API_KEY!
const STRAICO_API_BASE_URL = process.env.STRAICO_API_BASE_URL || 'https://api.straico.com/v1'

// Safety limits
const MAX_PROMPT_LENGTH = 4000
const MAX_RESPONSE_LENGTH = 16000
const API_TIMEOUT_MS = 30000
const MIN_PROMPT_LENGTH = 1

// Rate limiting (in-memory for MVP)
const rateLimitMap = new Map<string, { count: number; resetTime: number }>()
const RATE_LIMIT_WINDOW = 60000
const MAX_REQUESTS_PER_WINDOW = 10

// Hourly rate limiting for /api/generate (20 requests per hour per user)
const generateRateLimitMap = new Map<string, number[]>()
const GENERATE_RATE_LIMIT = 20
const GENERATE_RATE_WINDOW = 60 * 60 * 1000 // 1 hour in milliseconds

function checkGenerateRateLimit(userId: string): { allowed: boolean; remaining: number; retryAfterSeconds?: number } {
  const now = Date.now()
  const windowStart = now - GENERATE_RATE_WINDOW
  
  // Get existing timestamps or empty array
  let timestamps = generateRateLimitMap.get(userId) || []
  
  // Filter to only timestamps within the last hour
  timestamps = timestamps.filter(t => t > windowStart)
  
  // Check if limit exceeded
  if (timestamps.length >= GENERATE_RATE_LIMIT) {
    // Find oldest timestamp to calculate retry time
    const oldestTimestamp = Math.min(...timestamps)
    const retryAfterSeconds = Math.ceil((oldestTimestamp + GENERATE_RATE_WINDOW - now) / 1000)
    return { 
      allowed: false, 
      remaining: 0, 
      retryAfterSeconds 
    }
  }
  
  // Add current timestamp
  timestamps.push(now)
  generateRateLimitMap.set(userId, timestamps)
  
  return { 
    allowed: true, 
    remaining: GENERATE_RATE_LIMIT - timestamps.length 
  }
}

// Strict input sanitization
function sanitizeString(input: unknown): string | null {
  if (typeof input !== 'string') return null
  // Remove null bytes and control characters (except newlines and tabs)
  return input.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '').trim()
}

// Validate prompt strictly
function validatePrompt(input: unknown): { valid: boolean; prompt?: string; error?: string } {
  const sanitized = sanitizeString(input)
  
  if (sanitized === null) {
    return { valid: false, error: 'Prompt must be a string' }
  }
  
  if (sanitized.length < MIN_PROMPT_LENGTH) {
    return { valid: false, error: 'Prompt cannot be empty' }
  }
  
  if (sanitized.length > MAX_PROMPT_LENGTH) {
    return { valid: false, error: `Prompt cannot exceed ${MAX_PROMPT_LENGTH} characters` }
  }
  
  return { valid: true, prompt: sanitized }
}

// Truncate response to max length
function truncateResponse(response: string): string {
  if (response.length <= MAX_RESPONSE_LENGTH) return response
  return response.slice(0, MAX_RESPONSE_LENGTH) + '... [truncated]'
}

// Safe integer parsing
function safeParseInt(value: unknown, defaultValue: number): number {
  if (typeof value === 'number' && Number.isFinite(value)) {
    return Math.floor(value)
  }
  if (typeof value === 'string') {
    const parsed = parseInt(value, 10)
    if (Number.isFinite(parsed)) return parsed
  }
  return defaultValue
}

// Graceful error response helper
function errorResponse(message: string, status: number, details?: Record<string, unknown>): NextResponse {
  return handleCORS(NextResponse.json({
    error: message,
    status,
    timestamp: new Date().toISOString(),
    ...details
  }, { status }))
}

// CORS helper
function handleCORS(response: NextResponse): NextResponse {
  response.headers.set('Access-Control-Allow-Origin', process.env.CORS_ORIGINS || '*')
  response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
  response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization')
  response.headers.set('Access-Control-Allow-Credentials', 'true')
  return response
}

// Rate limit check
function checkRateLimit(userId: string): { allowed: boolean; remaining: number; retryAfter?: number } {
  const now = Date.now()
  const userKey = userId || 'anonymous'
  
  if (!rateLimitMap.has(userKey)) {
    rateLimitMap.set(userKey, { count: 1, resetTime: now + RATE_LIMIT_WINDOW })
    return { allowed: true, remaining: MAX_REQUESTS_PER_WINDOW - 1 }
  }
  
  const userData = rateLimitMap.get(userKey)!
  
  if (now > userData.resetTime) {
    rateLimitMap.set(userKey, { count: 1, resetTime: now + RATE_LIMIT_WINDOW })
    return { allowed: true, remaining: MAX_REQUESTS_PER_WINDOW - 1 }
  }
  
  if (userData.count >= MAX_REQUESTS_PER_WINDOW) {
    return { allowed: false, remaining: 0, retryAfter: Math.ceil((userData.resetTime - now) / 1000) }
  }
  
  userData.count++
  return { allowed: true, remaining: MAX_REQUESTS_PER_WINDOW - userData.count }
}

// Get user from auth header
async function getUserFromAuth(request: NextRequest) {
  const authHeader = request.headers.get('Authorization')
  if (!authHeader?.startsWith('Bearer ')) {
    return null
  }
  
  const token = authHeader.replace('Bearer ', '')
  const supabase = createAnonClient()
  
  const { data: { user }, error } = await supabase.auth.getUser(token)
  if (error || !user) {
    return null
  }
  
  return user
}

// Input validation
function validatePromptInput(prompt: unknown): { valid: boolean; prompt?: string; error?: string } {
  if (!prompt || typeof prompt !== 'string') {
    return { valid: false, error: 'Prompt is required and must be a string' }
  }
  
  const trimmed = prompt.trim()
  
  if (trimmed.length === 0) {
    return { valid: false, error: 'Prompt cannot be empty' }
  }
  
  if (trimmed.length > 10000) {
    return { valid: false, error: 'Prompt cannot exceed 10,000 characters' }
  }
  
  return { valid: true, prompt: trimmed }
}

export async function OPTIONS() {
  return handleCORS(new NextResponse(null, { status: 200 }))
}

async function handleRoute(request: NextRequest, { params }: RouteParams) {
  const { path = [] } = params
  const route = `/${path.join('/')}`
  const method = request.method

  try {
    // Root endpoint
    if ((route === '/root' || route === '/') && method === 'GET') {
      return handleCORS(NextResponse.json({ 
        message: 'AI Prompt Platform API',
        version: '1.0.0',
        endpoints: ['/auth/signup', '/auth/login', '/auth/logout', '/credits', '/prompt', '/history']
      }))
    }

    // Health check
    if (route === '/health' && method === 'GET') {
      return handleCORS(NextResponse.json({ status: 'healthy', timestamp: new Date().toISOString() }))
    }

    // ============ AUTH ENDPOINTS ============
    
    // Signup
    if (route === '/auth/signup' && method === 'POST') {
      const body = await request.json()
      const { email, password } = body
      
      if (!email || !password) {
        return handleCORS(NextResponse.json(
          { error: 'Email and password are required' },
          { status: 400 }
        ))
      }
      
      if (password.length < 6) {
        return handleCORS(NextResponse.json(
          { error: 'Password must be at least 6 characters' },
          { status: 400 }
        ))
      }
      
      const supabase = createAnonClient()
      const { data, error } = await supabase.auth.signUp({ email, password })
      
      if (error) {
        return handleCORS(NextResponse.json({ error: error.message }, { status: 400 }))
      }
      
      // Create profile with initial credits (server-side, safe upsert)
      if (data.user) {
        const serverClient = createServerClient()
        
        // Check if profile already exists
        const { data: existingProfile } = await serverClient
          .from('profiles')
          .select('id')
          .eq('id', data.user.id)
          .single()
        
        // Only insert if profile doesn't exist
        if (!existingProfile) {
          await serverClient.from('profiles').insert({
            id: data.user.id,
            email: data.user.email,
            credits_remaining: INITIAL_CREDITS
          })
        }
      }
      
      return handleCORS(NextResponse.json({
        message: 'User created successfully',
        user: data.user ? { id: data.user.id, email: data.user.email } : null,
        session: data.session
      }))
    }
    
    // Login
    if (route === '/auth/login' && method === 'POST') {
      const body = await request.json()
      const { email, password } = body
      
      if (!email || !password) {
        return handleCORS(NextResponse.json(
          { error: 'Email and password are required' },
          { status: 400 }
        ))
      }
      
      const supabase = createAnonClient()
      const { data, error } = await supabase.auth.signInWithPassword({ email, password })
      
      if (error) {
        return handleCORS(NextResponse.json({ error: error.message }, { status: 401 }))
      }
      
      // Ensure user has profile
      if (data.user) {
        const serverClient = createServerClient()
        const { data: profileData } = await serverClient
          .from('profiles')
          .select('credits_remaining')
          .eq('id', data.user.id)
          .single()
        
        if (!profileData) {
          await serverClient.from('profiles').insert({
            id: data.user.id,
            email: data.user.email,
            credits_remaining: INITIAL_CREDITS,
            created_at: new Date().toISOString()
          })
        }
      }
      
      return handleCORS(NextResponse.json({
        message: 'Login successful',
        user: { id: data.user.id, email: data.user.email },
        session: data.session
      }))
    }
    
    // Logout
    if (route === '/auth/logout' && method === 'POST') {
      return handleCORS(NextResponse.json({ message: 'Logout successful' }))
    }

    // ============ CREDITS ENDPOINT ============
    
    if (route === '/credits' && method === 'GET') {
      const user = await getUserFromAuth(request)
      if (!user) {
        return handleCORS(NextResponse.json({ error: 'Unauthorized' }, { status: 401 }))
      }
      
      const serverClient = createServerClient()
      const { data, error } = await serverClient
        .from('profiles')
        .select('credits_remaining, created_at')
        .eq('id', user.id)
        .single()
      
      if (error || !data) {
        // Create profile if doesn't exist
        await serverClient.from('profiles').insert({
          id: user.id,
          email: user.email,
          credits_remaining: INITIAL_CREDITS,
          created_at: new Date().toISOString()
        })
        return handleCORS(NextResponse.json({ credits: INITIAL_CREDITS }))
      }
      
      return handleCORS(NextResponse.json({ credits: data.credits_remaining }))
    }

    // ============ GENERATE ENDPOINT ============
    
    if (route === '/generate' && method === 'POST') {
      const user = await getUserFromAuth(request)
      if (!user) {
        return errorResponse('Unauthorized', 401)
      }
      
      // Hourly rate limiting: 20 requests per hour per user
      const rateLimit = checkGenerateRateLimit(user.id)
      if (!rateLimit.allowed) {
        const minutes = Math.ceil((rateLimit.retryAfterSeconds || 0) / 60)
        return errorResponse(
          `Rate limit exceeded. You can make ${GENERATE_RATE_LIMIT} requests per hour. Try again in ${minutes} minute${minutes !== 1 ? 's' : ''}.`,
          429,
          { retry_after_seconds: rateLimit.retryAfterSeconds, requests_remaining: 0 }
        )
      }
      
      // Parse and validate JSON body
      let body: Record<string, unknown>
      try {
        body = await request.json()
        if (typeof body !== 'object' || body === null) {
          return errorResponse('Request body must be a JSON object', 400)
        }
      } catch {
        return errorResponse('Invalid JSON body', 400)
      }
      
      // Strict input validation
      const validation = validatePrompt(body.prompt)
      if (!validation.valid) {
        return errorResponse(validation.error!, 400)
      }
      const sanitizedPrompt = validation.prompt!
      
      const serverClient = createServerClient()
      
      // Fetch current credits with row-level lock simulation
      const { data: profile, error: profileError } = await serverClient
        .from('profiles')
        .select('credits_remaining')
        .eq('id', user.id)
        .single()
      
      if (profileError || !profile) {
        return errorResponse('Profile not found', 404)
      }
      
      // Ensure credits is a valid number and > 0
      const currentCredits = safeParseInt(profile.credits_remaining, 0)
      if (currentCredits <= 0) {
        return errorResponse('Insufficient credits', 402, { credits_remaining: 0 })
      }
      
      // Call Straico API with strict timeout
      const controller = new AbortController()
      const timeoutId = setTimeout(() => controller.abort(), API_TIMEOUT_MS)
      
      let straicoData: any
      
      try {
        const straicoResponse = await fetch(`${STRAICO_API_BASE_URL}/prompt/completion`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${STRAICO_API_KEY}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            model: 'openai/gpt-4o-mini',
            message: sanitizedPrompt,
            max_tokens: MAX_TOKENS
          }),
          signal: controller.signal
        })
        
        clearTimeout(timeoutId)
        
        if (!straicoResponse.ok) {
          const errorText = await straicoResponse.text().catch(() => 'Unknown error')
          console.error('Straico API error:', straicoResponse.status, errorText)
          return errorResponse('AI service error', 502)
        }
        
        straicoData = await straicoResponse.json()
      } catch (fetchError: any) {
        clearTimeout(timeoutId)
        if (fetchError.name === 'AbortError') {
          return errorResponse('Request timeout - AI service took too long', 504)
        }
        console.error('Straico fetch error:', fetchError.message || fetchError)
        return errorResponse('AI service unavailable', 503)
      }
      
      // Extract and validate response text
      let responseText = ''
      if (straicoData.data?.completion?.choices?.[0]?.message?.content) {
        responseText = String(straicoData.data.completion.choices[0].message.content)
      } else if (straicoData.data?.completion) {
        responseText = String(straicoData.data.completion)
      } else if (straicoData.completion) {
        responseText = String(straicoData.completion)
      }
      
      if (!responseText || responseText.trim().length === 0) {
        return errorResponse('No response from AI', 502)
      }
      
      // Truncate response to max length for safety
      responseText = truncateResponse(responseText)
      
      // Calculate tokens used (use API value or estimate)
      let tokensUsed = safeParseInt(
        straicoData.data?.usage?.total_tokens 
        || straicoData.data?.words 
        || straicoData.usage?.total_tokens,
        0
      )
      
      if (tokensUsed <= 0) {
        // Estimate: 1 token ≈ 4 characters
        const inputTokens = Math.ceil(sanitizedPrompt.length / 4)
        const outputTokens = Math.ceil(responseText.length / 4)
        tokensUsed = inputTokens + outputTokens
      }
      
      // Ensure tokens is positive and reasonable
      tokensUsed = Math.min(Math.max(1, tokensUsed), 100000)
      
      // ATOMIC credits deduction - server-side only, prevent negative
      // Re-fetch to ensure we have latest value before deduction
      const { data: freshProfile, error: freshError } = await serverClient
        .from('profiles')
        .select('credits_remaining')
        .eq('id', user.id)
        .single()
      
      if (freshError || !freshProfile) {
        return errorResponse('Failed to verify credits', 500)
      }
      
      const latestCredits = safeParseInt(freshProfile.credits_remaining, 0)
      
      // Prevent negative credits - ensure we have enough
      if (latestCredits < tokensUsed) {
        // Deduct only what's available, set to 0
        const { error: updateError } = await serverClient
          .from('profiles')
          .update({ credits_remaining: 0 })
          .eq('id', user.id)
          .gte('credits_remaining', 0) // Extra safety: only if >= 0
        
        if (updateError) {
          console.error('Failed to update credits:', updateError)
        }
        
        return errorResponse('Insufficient credits for this request', 402, { 
          credits_remaining: 0,
          tokens_required: tokensUsed
        })
      }
      
      // Deduct credits atomically (server-side only)
      const newCredits = Math.max(0, latestCredits - tokensUsed)
      
      const { error: updateError } = await serverClient
        .from('profiles')
        .update({ credits_remaining: newCredits })
        .eq('id', user.id)
        .gte('credits_remaining', tokensUsed) // Only update if sufficient credits
      
      if (updateError) {
        console.error('Failed to update credits:', updateError)
        // Don't fail the request, but log the issue
      }
      
      // Insert record into prompt_logs
      const { error: logError } = await serverClient.from('prompt_logs').insert({
        user_id: user.id,
        prompt: sanitizedPrompt,
        response: responseText,
        tokens_used: tokensUsed
      })
      
      if (logError) {
        console.error('Failed to insert prompt log:', logError)
      }
      
      // Return success response
      return handleCORS(NextResponse.json({
        response: responseText,
        tokens_used: tokensUsed,
        credits_remaining: newCredits,
        requests_remaining: rateLimit.remaining
      }))
    }

    // ============ PROMPT ENDPOINT (legacy) ============
    
    if (route === '/prompt' && method === 'POST') {
      const user = await getUserFromAuth(request)
      if (!user) {
        return handleCORS(NextResponse.json({ error: 'Unauthorized' }, { status: 401 }))
      }
      
      // Rate limiting
      const rateLimit = checkRateLimit(user.id)
      if (!rateLimit.allowed) {
        return handleCORS(NextResponse.json(
          { error: 'Rate limit exceeded', retryAfter: rateLimit.retryAfter },
          { status: 429 }
        ))
      }
      
      const body = await request.json()
      const validation = validatePromptInput(body.prompt)
      
      if (!validation.valid) {
        return handleCORS(NextResponse.json({ error: validation.error }, { status: 400 }))
      }
      
      const serverClient = createServerClient()
      
      // Check credits from profiles table
      const { data: profileData, error: profileError } = await serverClient
        .from('profiles')
        .select('credits_remaining')
        .eq('id', user.id)
        .single()
      
      if (profileError || !profileData) {
        return handleCORS(NextResponse.json({ error: 'Unable to fetch credits' }, { status: 500 }))
      }
      
      if (profileData.credits_remaining < CREDITS_PER_REQUEST) {
        return handleCORS(NextResponse.json(
          { error: 'Insufficient credits', credits: profileData.credits_remaining },
          { status: 402 }
        ))
      }
      
      // Call Straico API
      const straicoResponse = await fetch(`${STRAICO_API_BASE_URL}/prompt/completion`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${STRAICO_API_KEY}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model: 'openai/gpt-4o-mini',
          message: validation.prompt,
          max_tokens: MAX_TOKENS
        })
      })
      
      if (!straicoResponse.ok) {
        console.error('Straico API error:', await straicoResponse.text())
        return handleCORS(NextResponse.json({ error: 'AI service error' }, { status: 502 }))
      }
      
      const straicoData = await straicoResponse.json()
      
      // Extract response
      let responseText = ''
      if (straicoData.data?.completion?.choices?.[0]?.message?.content) {
        responseText = straicoData.data.completion.choices[0].message.content
      } else if (straicoData.data?.completion) {
        responseText = String(straicoData.data.completion)
      } else {
        responseText = JSON.stringify(straicoData)
      }
      
      // Get tokens used
      const tokensUsed = straicoData.data?.words || 0
      
      // Deduct credits from profiles table
      const newCredits = profileData.credits_remaining - CREDITS_PER_REQUEST
      await serverClient
        .from('profiles')
        .update({ credits_remaining: newCredits })
        .eq('id', user.id)
      
      // Store in prompt_logs table
      await serverClient.from('prompt_logs').insert({
        user_id: user.id,
        prompt: validation.prompt,
        response: responseText,
        tokens_used: tokensUsed,
        created_at: new Date().toISOString()
      })
      
      return handleCORS(NextResponse.json({
        response: responseText,
        tokensUsed,
        creditsRemaining: newCredits
      }))
    }

    // ============ HISTORY ENDPOINT ============
    
    if (route === '/history' && method === 'GET') {
      const user = await getUserFromAuth(request)
      if (!user) {
        return handleCORS(NextResponse.json({ error: 'Unauthorized' }, { status: 401 }))
      }
      
      const serverClient = createServerClient()
      const { data, error } = await serverClient
        .from('prompt_logs')
        .select('id, prompt, response, tokens_used, created_at')
        .eq('user_id', user.id)
        .order('created_at', { ascending: false })
        .limit(50)
      
      if (error) {
        return handleCORS(NextResponse.json({ error: 'Failed to fetch history' }, { status: 500 }))
      }
      
      return handleCORS(NextResponse.json({ history: data || [] }))
    }

    // Not found
    return handleCORS(NextResponse.json({ error: `Route ${route} not found` }, { status: 404 }))

  } catch (error) {
    console.error('API Error:', error)
    return handleCORS(NextResponse.json({ error: 'Internal server error' }, { status: 500 }))
  }
}

export const GET = handleRoute
export const POST = handleRoute
export const PUT = handleRoute
export const DELETE = handleRoute
export const PATCH = handleRoute
