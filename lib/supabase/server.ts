import { createServerClient } from '@supabase/ssr'
import { cookies } from 'next/headers'

export async function createClient() {
  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL
  const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY

  // During build, env vars may not be available
  if (!supabaseUrl || !supabaseAnonKey) {
    // Return a mock client that will fail auth checks gracefully
    return {
      auth: {
        getUser: async () => ({ data: { user: null }, error: { message: 'Not configured' } }),
        getSession: async () => ({ data: { session: null }, error: null }),
        signOut: async () => ({ error: null })
      }
    } as any
  }

  const cookieStore = await cookies()

  return createServerClient(
    supabaseUrl,
    supabaseAnonKey,
    {
      cookies: {
        getAll() {
          return cookieStore.getAll()
        },
        setAll(cookiesToSet) {
          try {
            cookiesToSet.forEach(({ name, value, options }) =>
              cookieStore.set(name, value, options)
            )
          } catch {
            // The `setAll` method was called from a Server Component.
          }
        },
      },
    }
  )
}
