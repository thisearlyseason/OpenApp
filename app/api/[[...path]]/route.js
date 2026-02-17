import { createClient } from '@supabase/supabase-js'
import { v4 as uuidv4 } from 'uuid'
import { NextResponse } from 'next/server'

// Supabase clients
function createServerClient() {
  return createClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY,
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
    process.env.NEXT_PUBLIC_SUPABASE_URL,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY
  )
}

// Constants
const INITIAL_CREDITS = parseInt(process.env.INITIAL_CREDITS) || 100
const CREDITS_PER_REQUEST = parseInt(process.env.CREDITS_PER_REQUEST) || 1
const MAX_TOKENS = parseInt(process.env.MAX_TOKENS) || 2000
const STRAICO_API_KEY = process.env.STRAICO_API_KEY
const STRAICO_API_BASE_URL = process.env.STRAICO_API_BASE_URL || 'https://api.straico.com/v1'

// Rate limiting storage (in-memory for MVP)
const rateLimitMap = new Map()
const RATE_LIMIT_WINDOW = 60000 // 1 minute
const MAX_REQUESTS_PER_WINDOW = 10

// Helper function to handle CORS
function handleCORS(response) {
  response.headers.set('Access-Control-Allow-Origin', process.env.CORS_ORIGINS || '*')
  response.headers.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
  response.headers.set('Access-Control-Allow-Headers', 'Content-Type, Authorization')
  response.headers.set('Access-Control-Allow-Credentials', 'true')
  return response
}

// Rate limiting check
function checkRateLimit(userId) {
  const now = Date.now()
  const userKey = userId || 'anonymous'
  
  if (!rateLimitMap.has(userKey)) {
    rateLimitMap.set(userKey, { count: 1, resetTime: now + RATE_LIMIT_WINDOW })
    return { allowed: true, remaining: MAX_REQUESTS_PER_WINDOW - 1 }
  }
  
  const userData = rateLimitMap.get(userKey)
  
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
async function getUserFromAuth(request) {
  const authHeader = request.headers.get('Authorization')
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
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
function validatePromptInput(prompt) {
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

// OPTIONS handler for CORS
export async function OPTIONS() {
  return handleCORS(new NextResponse(null, { status: 200 }))
}

// Route handler function
async function handleRoute(request, { params }) {
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
    
    // Signup - POST /api/auth/signup
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
      const { data, error } = await supabase.auth.signUp({
        email,
        password
      })
      
      if (error) {
        return handleCORS(NextResponse.json(
          { error: error.message },
          { status: 400 }
        ))
      }
      
      // Create initial credits for new user
      if (data.user) {
        const serverClient = createServerClient()
        await serverClient.from('user_credits').upsert({
          user_id: data.user.id,
          credits: INITIAL_CREDITS,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        })
      }
      
      return handleCORS(NextResponse.json({
        message: 'User created successfully',
        user: data.user ? { id: data.user.id, email: data.user.email } : null,
        session: data.session
      }))
    }
    
    // Login - POST /api/auth/login
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
      const { data, error } = await supabase.auth.signInWithPassword({
        email,
        password
      })
      
      if (error) {
        return handleCORS(NextResponse.json(
          { error: error.message },
          { status: 401 }
        ))
      }
      
      // Ensure user has credits record
      if (data.user) {
        const serverClient = createServerClient()
        const { data: creditsData } = await serverClient
          .from('user_credits')
          .select('credits')
          .eq('user_id', data.user.id)
          .single()
        
        if (!creditsData) {
          await serverClient.from('user_credits').insert({
            user_id: data.user.id,
            credits: INITIAL_CREDITS,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
          })
        }
      }
      
      return handleCORS(NextResponse.json({
        message: 'Login successful',
        user: { id: data.user.id, email: data.user.email },
        session: data.session
      }))
    }
    
    // Logout - POST /api/auth/logout
    if (route === '/auth/logout' && method === 'POST') {
      return handleCORS(NextResponse.json({ message: 'Logout successful' }))
    }

    // ============ CREDITS ENDPOINTS ============
    
    // Get credits - GET /api/credits
    if (route === '/credits' && method === 'GET') {
      const user = await getUserFromAuth(request)
      if (!user) {
        return handleCORS(NextResponse.json(
          { error: 'Unauthorized' },
          { status: 401 }
        ))
      }
      
      const serverClient = createServerClient()
      const { data, error } = await serverClient
        .from('user_credits')
        .select('credits, updated_at')
        .eq('user_id', user.id)
        .single()
      
      if (error || !data) {
        // Create credits if not exists
        await serverClient.from('user_credits').insert({
          user_id: user.id,
          credits: INITIAL_CREDITS,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        })
        return handleCORS(NextResponse.json({ credits: INITIAL_CREDITS }))
      }
      
      return handleCORS(NextResponse.json({ 
        credits: data.credits,
        lastUpdated: data.updated_at
      }))
    }

    // ============ PROMPT ENDPOINT ============
    
    // Submit prompt - POST /api/prompt
    if (route === '/prompt' && method === 'POST') {
      const user = await getUserFromAuth(request)
      if (!user) {
        return handleCORS(NextResponse.json(
          { error: 'Unauthorized' },
          { status: 401 }
        ))
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
        return handleCORS(NextResponse.json(
          { error: validation.error },
          { status: 400 }
        ))
      }
      
      const serverClient = createServerClient()
      
      // Check user credits
      const { data: creditsData, error: creditsError } = await serverClient
        .from('user_credits')
        .select('credits')
        .eq('user_id', user.id)
        .single()
      
      if (creditsError || !creditsData) {
        return handleCORS(NextResponse.json(
          { error: 'Unable to fetch credits' },
          { status: 500 }
        ))
      }
      
      if (creditsData.credits < CREDITS_PER_REQUEST) {
        return handleCORS(NextResponse.json(
          { error: 'Insufficient credits', credits: creditsData.credits },
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
        const errorText = await straicoResponse.text()
        console.error('Straico API error:', errorText)
        return handleCORS(NextResponse.json(
          { error: 'AI service error' },
          { status: 502 }
        ))
      }
      
      const straicoData = await straicoResponse.json()
      
      // Extract response text
      let responseText = ''
      if (straicoData.data && straicoData.data.completion) {
        responseText = straicoData.data.completion.choices?.[0]?.message?.content || straicoData.data.completion
      } else if (straicoData.completion) {
        responseText = straicoData.completion
      } else if (typeof straicoData === 'string') {
        responseText = straicoData
      } else {
        responseText = JSON.stringify(straicoData)
      }
      
      // Deduct credits (server-side)
      const newCredits = creditsData.credits - CREDITS_PER_REQUEST
      await serverClient
        .from('user_credits')
        .update({ credits: newCredits, updated_at: new Date().toISOString() })
        .eq('user_id', user.id)
      
      // Get tokens used
      const tokensUsed = straicoData.data?.words || straicoData.words || 0
      
      // Store in history
      const historyId = uuidv4()
      await serverClient.from('prompt_history').insert({
        id: historyId,
        user_id: user.id,
        prompt: validation.prompt,
        response: responseText,
        tokens_used: tokensUsed,
        credits_used: CREDITS_PER_REQUEST,
        created_at: new Date().toISOString()
      })
      
      return handleCORS(NextResponse.json({
        response: responseText,
        tokensUsed,
        creditsRemaining: newCredits,
        historyId
      }))
    }

    // ============ HISTORY ENDPOINTS ============
    
    // Get history - GET /api/history
    if (route === '/history' && method === 'GET') {
      const user = await getUserFromAuth(request)
      if (!user) {
        return handleCORS(NextResponse.json(
          { error: 'Unauthorized' },
          { status: 401 }
        ))
      }
      
      const serverClient = createServerClient()
      const { data, error } = await serverClient
        .from('prompt_history')
        .select('id, prompt, response, tokens_used, credits_used, created_at')
        .eq('user_id', user.id)
        .order('created_at', { ascending: false })
        .limit(50)
      
      if (error) {
        return handleCORS(NextResponse.json(
          { error: 'Failed to fetch history' },
          { status: 500 }
        ))
      }
      
      return handleCORS(NextResponse.json({ history: data || [] }))
    }

    // Route not found
    return handleCORS(NextResponse.json(
      { error: `Route ${route} not found` },
      { status: 404 }
    ))

  } catch (error) {
    console.error('API Error:', error)
    return handleCORS(NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    ))
  }
}

// Export all HTTP methods
export const GET = handleRoute
export const POST = handleRoute
export const PUT = handleRoute
export const DELETE = handleRoute
export const PATCH = handleRoute
