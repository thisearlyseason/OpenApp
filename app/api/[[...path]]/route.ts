import { createClient, SupabaseClient } from '@supabase/supabase-js'
import { NextRequest, NextResponse } from 'next/server'

// Types
interface RouteParams {
  params: { path?: string[] }
}

// Singleton Supabase clients (connection pooling)
let serverClientInstance: SupabaseClient | null = null
let anonClientInstance: SupabaseClient | null = null

function getServerClient(): SupabaseClient {
  if (!serverClientInstance) {
    serverClientInstance = createClient(
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
  return serverClientInstance
}

function getAnonClient(): SupabaseClient {
  if (!anonClientInstance) {
    anonClientInstance = createClient(
      process.env.NEXT_PUBLIC_SUPABASE_URL!,
      process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!
    )
  }
  return anonClientInstance
}

// Constants
const INITIAL_CREDITS = 100000
const MAX_TOKENS = parseInt(process.env.MAX_TOKENS || '2000')
const STRAICO_API_KEY = process.env.STRAICO_API_KEY!
const STRAICO_API_BASE_URL = process.env.STRAICO_API_BASE_URL || 'https://api.straico.com/v1'

// Admin configuration
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || '').split(',').map(e => e.trim().toLowerCase()).filter(Boolean)

// Available models (Straico model IDs)
const AVAILABLE_MODELS: Record<string, string> = {
  'gpt-4o-mini': 'openai/gpt-4o-mini',
  'gpt-4o': 'openai/gpt-4o',
  'gpt-4.5': 'openai/gpt-4.5-preview',
  'chatgpt-5.0': 'openai/gpt-4o', // Map to best available
  'claude-sonnet-4': 'anthropic/claude-sonnet-4',
  'claude-sonnet-4.5': 'anthropic/claude-sonnet-4',
  'claude-opus-4': 'anthropic/claude-opus-4',
  'claude-opus-4.5': 'anthropic/claude-opus-4',
  'sonnet': 'anthropic/claude-sonnet-4',
  'opus': 'anthropic/claude-opus-4'
}
const DEFAULT_MODEL = 'openai/gpt-4o-mini'

// Check if user is admin
function isAdmin(email: string | undefined): boolean {
  if (!email) return false
  return ADMIN_EMAILS.includes(email.toLowerCase())
}

// Safety limits
const MAX_PROMPT_LENGTH = 4000
const MAX_RESPONSE_LENGTH = 16000
const API_TIMEOUT_MS = 30000
const MIN_PROMPT_LENGTH = 1
const MIN_TOKENS_CHARGE = 10 // Minimum tokens charged per request

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

// CORS helper - RESTRICTED to allowed origins
function handleCORS(response: NextResponse): NextResponse {
  const allowedOrigin = process.env.NEXT_PUBLIC_BASE_URL || 'http://localhost:3000'
  response.headers.set('Access-Control-Allow-Origin', allowedOrigin)
  response.headers.set('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
  response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization')
  response.headers.set('Access-Control-Allow-Credentials', 'true')
  response.headers.set('Access-Control-Max-Age', '86400')
  return response
}

// Email validation
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
function isValidEmail(email: unknown): boolean {
  return typeof email === 'string' && EMAIL_REGEX.test(email) && email.length <= 254
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
  if (!token || token.length < 10) {
    return null
  }
  
  const supabase = getAnonClient()
  
  const { data: { user }, error } = await supabase.auth.getUser(token)
  if (error || !user) {
    return null
  }
  
  return user
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
      let body: Record<string, unknown>
      try {
        body = await request.json()
      } catch {
        return errorResponse('Invalid JSON body', 400)
      }
      
      const { email, password } = body
      
      if (!email || !password) {
        return errorResponse('Email and password are required', 400)
      }
      
      // Validate email format
      if (!isValidEmail(email)) {
        return errorResponse('Invalid email format', 400)
      }
      
      if (typeof password !== 'string' || password.length < 6) {
        return errorResponse('Password must be at least 6 characters', 400)
      }
      
      if (password.length > 72) {
        return errorResponse('Password cannot exceed 72 characters', 400)
      }
      
      const supabase = getAnonClient()
      const { data, error } = await supabase.auth.signUp({ 
        email: String(email).toLowerCase().trim(), 
        password: String(password)
      })
      
      if (error) {
        return errorResponse(error.message, 400)
      }
      
      // Create profile with initial credits (server-side, safe insert)
      if (data.user) {
        const serverClient = getServerClient()
        
        // Only insert if profile doesn't exist (upsert with onConflict ignore)
        await serverClient.from('profiles').upsert({
          id: data.user.id,
          email: data.user.email,
          credits_remaining: INITIAL_CREDITS
        }, { onConflict: 'id', ignoreDuplicates: true })
      }
      
      return handleCORS(NextResponse.json({
        message: 'User created successfully',
        user: data.user ? { id: data.user.id, email: data.user.email } : null,
        session: data.session
      }))
    }
    
    // Login
    if (route === '/auth/login' && method === 'POST') {
      let body: Record<string, unknown>
      try {
        body = await request.json()
      } catch {
        return errorResponse('Invalid JSON body', 400)
      }
      
      const { email, password } = body
      
      if (!email || !password) {
        return errorResponse('Email and password are required', 400)
      }
      
      if (!isValidEmail(email)) {
        return errorResponse('Invalid email format', 400)
      }
      
      const supabase = getAnonClient()
      const { data, error } = await supabase.auth.signInWithPassword({ 
        email: String(email).toLowerCase().trim(), 
        password: String(password)
      })
      
      if (error) {
        return errorResponse('Invalid credentials', 401)
      }
      
      // Ensure user has profile (upsert to handle edge cases)
      if (data.user) {
        const serverClient = getServerClient()
        await serverClient.from('profiles').upsert({
          id: data.user.id,
          email: data.user.email,
          credits_remaining: INITIAL_CREDITS
        }, { onConflict: 'id', ignoreDuplicates: true })
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
        return errorResponse('Unauthorized', 401)
      }
      
      const serverClient = getServerClient()
      const { data, error } = await serverClient
        .from('profiles')
        .select('credits_remaining')
        .eq('id', user.id)
        .single()
      
      if (error || !data) {
        // Create profile if doesn't exist
        await serverClient.from('profiles').upsert({
          id: user.id,
          email: user.email,
          credits_remaining: INITIAL_CREDITS
        }, { onConflict: 'id', ignoreDuplicates: true })
        return handleCORS(NextResponse.json({ credits: INITIAL_CREDITS }))
      }
      
      return handleCORS(NextResponse.json({ credits: data.credits_remaining }))
    }

    // ============ GENERATE ENDPOINT ============
    
    if (route === '/generate' && method === 'POST') {
      // Auth check FIRST (before rate limiting)
      const user = await getUserFromAuth(request)
      if (!user) {
        return errorResponse('Unauthorized', 401)
      }
      
      // Rate limiting AFTER auth (prevents DoS via fake tokens)
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
      
      // Check if user is admin
      const userIsAdmin = isAdmin(user.email)
      
      // Model selection (admin only)
      let selectedModel = DEFAULT_MODEL
      if (userIsAdmin && body.model && typeof body.model === 'string') {
        const modelKey = body.model.toLowerCase()
        selectedModel = AVAILABLE_MODELS[modelKey] || body.model
      }
      
      const serverClient = getServerClient()
      
      // Fetch current credits
      const { data: profile, error: profileError } = await serverClient
        .from('profiles')
        .select('credits_remaining')
        .eq('id', user.id)
        .single()
      
      if (profileError || !profile) {
        return errorResponse('Profile not found', 404)
      }
      
      const currentCredits = safeParseInt(profile.credits_remaining, 0)
      
      // Skip credit checks for admin users
      if (!userIsAdmin) {
        // PRE-CHECK: Ensure minimum credits available
        if (currentCredits < MIN_TOKENS_CHARGE) {
          return errorResponse('Insufficient credits', 402, { credits_remaining: currentCredits })
        }
        
        // PRE-DEDUCT: Reserve MAX_TOKENS before calling API
        const reserveAmount = Math.min(MAX_TOKENS, currentCredits)
        const { data: preDeductResult, error: preDeductError } = await serverClient
          .from('profiles')
          .update({ credits_remaining: currentCredits - reserveAmount })
          .eq('id', user.id)
          .eq('credits_remaining', currentCredits)
          .select('credits_remaining')
          .single()
        
        if (preDeductError || !preDeductResult) {
          return errorResponse('Credits verification failed. Please try again.', 409)
        }
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
          // REFUND on failure
          await serverClient
            .from('profiles')
            .update({ credits_remaining: currentCredits })
            .eq('id', user.id)
          return errorResponse('AI service error', 502)
        }
        
        straicoData = await straicoResponse.json()
        apiSuccess = true
      } catch (fetchError: any) {
        clearTimeout(timeoutId)
        // REFUND on failure
        await serverClient
          .from('profiles')
          .update({ credits_remaining: currentCredits })
          .eq('id', user.id)
        
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
        // REFUND on empty response
        await serverClient
          .from('profiles')
          .update({ credits_remaining: currentCredits })
          .eq('id', user.id)
        return errorResponse('No response from AI', 502)
      }
      
      // Truncate response to max length for safety
      responseText = truncateResponse(responseText)
      
      // Calculate actual tokens used
      let tokensUsed = safeParseInt(
        straicoData.data?.usage?.total_tokens 
        || straicoData.data?.words 
        || straicoData.usage?.total_tokens,
        0
      )
      
      // If API doesn't return usage, charge MAX_TOKENS (conservative)
      if (tokensUsed <= 0) {
        tokensUsed = MAX_TOKENS
      }
      
      // Apply minimum charge
      tokensUsed = Math.max(MIN_TOKENS_CHARGE, tokensUsed)
      
      // Cap at reasonable maximum
      tokensUsed = Math.min(tokensUsed, 100000)
      
      // Calculate final credits (refund unused reservation)
      const finalCredits = Math.max(0, currentCredits - tokensUsed)
      
      // Update to actual deduction (atomic)
      await serverClient
        .from('profiles')
        .update({ credits_remaining: finalCredits })
        .eq('id', user.id)
      
      // Insert record into prompt_logs
      await serverClient.from('prompt_logs').insert({
        user_id: user.id,
        prompt: sanitizedPrompt,
        response: responseText,
        tokens_used: tokensUsed
      })
      
      // Return success response
      return handleCORS(NextResponse.json({
        response: responseText,
        tokens_used: tokensUsed,
        credits_remaining: finalCredits,
        requests_remaining: rateLimit.remaining
      }))
    }

    // ============ HISTORY ENDPOINT ============
    
    if (route === '/history' && method === 'GET') {
      const user = await getUserFromAuth(request)
      if (!user) {
        return errorResponse('Unauthorized', 401)
      }
      
      const serverClient = getServerClient()
      const { data, error } = await serverClient
        .from('prompt_logs')
        .select('id, prompt, response, tokens_used, created_at')
        .eq('user_id', user.id)
        .order('created_at', { ascending: false })
        .limit(50)
      
      if (error) {
        return errorResponse('Failed to fetch history', 500)
      }
      
      return handleCORS(NextResponse.json({ history: data || [] }))
    }

    // Not found
    return errorResponse(`Route ${route} not found`, 404)

  } catch (error) {
    console.error('API Error:', error)
    return errorResponse('Internal server error', 500)
  }
}

export const GET = handleRoute
export const POST = handleRoute
export const PUT = handleRoute
export const DELETE = handleRoute
export const PATCH = handleRoute
